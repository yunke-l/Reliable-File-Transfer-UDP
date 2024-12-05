import socket
import struct
import sys
from struct import pack, unpack
from time import sleep

CLIENT_IP = "172.31.21.219"
SERVER_IP = "172.31.21.112"
# CLIENT_IP = "127.0.0.1"
# SERVER_IP = "127.0.0.1"
CLIENT_PORT = 3434
SERVER_PORT = 50100


# creating socket
def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except socket.error as msg:
        print(
            "Socket could not be created. Error Code : "
            + str(msg[0])
            + " Message "
            + msg[1]
        )
        sys.exit()
    try:
        s.bind((CLIENT_IP, CLIENT_PORT))
    except socket.error as msg:
        print("Bind failed. Error: " + str(msg[0]) + ": " + msg[1])
        sys.exit()
    return s


# calculate checksum for the given data
def checksum(data):
    if len(data) % 2 != 0:
        data += b"\x00"
    res = sum(
        int.from_bytes(data[i : i + 2], byteorder="big") for i in range(0, len(data), 2)
    )
    res = (res >> 16) + (res & 0xFFFF)
    res = res + (res >> 16)
    return (~res) & 0xFFFF


# create the IP header
def create_IP_header(src_ip, dst_ip, payload: bytes):
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 36 + len(payload)
    ip_id = 12345
    ip_frag_off = 0x4000  # Don't fragment
    ip_ttl = 64
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ihl_ver,
        ip_tos,
        ip_tot_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_check,
        ip_saddr,
        ip_daddr,
    )
    return ip_header

# construct UDP header
def create_UDP_header(src_port, dst_port, payload: bytes, seq_number, ack_number):

    udp_length = 16 + len(payload)
    checksum_zero = 0
    udp_header = pack(
        "!HHHiiH", src_port, dst_port, udp_length, seq_number, ack_number, checksum_zero
    )

    checksum_data = udp_header + payload

    computed_checksum = checksum(checksum_data)

    udp_header_with_checksum = pack(
        "!HHHiiH",
        src_port,
        dst_port,
        udp_length,
        seq_number,
        ack_number,
        computed_checksum,
    )
    return udp_header_with_checksum


# receive UDP packets
def receive_udp(passed_socket):
    receiving_socket = passed_socket
    try:
        data = receiving_socket.recv(65535)
    except KeyboardInterrupt:
        print("Shutting down.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

    return {"data": data}

# extract payloads from packets
def extract_payloads(packet):
    if packet is None:
        return None

    data = packet["data"]
    if len(data) < 36:  # if the packet is not a data packet
        return None

    # unpack udp header
    udp_header = data[20:36]
    udp_unpack = unpack("!HHHiiH", udp_header)
    udp_fields = {
        "source_port": udp_unpack[0],
        "dest_port": udp_unpack[1],
        # "udp_length": udp_unpack[2],
        "seq_number": udp_unpack[3],
        "ack_number": udp_unpack[4],
        "checksum": udp_unpack[5],
    }

    # unpack the ip header
    ip_header = data[:20]
    ip_unpack = unpack("!BBHHHBBH4s4s", ip_header)
    ip_fields = {
        "ip_saddr": ip_unpack[8],
        "ip_daddr": ip_unpack[9],
    }

    str_ip_saddr = socket.inet_ntoa(ip_fields["ip_saddr"])  # source ip string
    str_ip_daddr = socket.inet_ntoa(ip_fields["ip_daddr"])  # destination ip string

    # filtering packet: the packet is not from the server or to the client
    if str_ip_saddr != SERVER_IP or str_ip_daddr != CLIENT_IP:
        return None

    # filtering packet: in case loopback packet
    if (
        udp_fields["dest_port"] != CLIENT_PORT
        or udp_fields["source_port"] != SERVER_PORT
    ):
        return None

    # check the checksum
    checksum_data = data[20:]
    computed_checksum = checksum(checksum_data)
    if computed_checksum != 0:
        print("Checksum failed")
        return None
    payload = data[36:]

    return [payload, udp_fields["seq_number"], udp_fields["ack_number"]]

def send_udp(
    passed_socket,
    payload: bytes,
    seq_number,
    ack_number,
    src_ip=CLIENT_IP,
    dst_ip=SERVER_IP,
    src_port=CLIENT_PORT,
    dst_port=SERVER_PORT,
):
    ip_header = create_IP_header(src_ip, dst_ip, payload)
    udp_header = create_UDP_header(src_port, dst_port, payload, seq_number, ack_number)

    packet = ip_header + udp_header + payload
    passed_socket.sendto(packet, (dst_ip, 0))


def main():
    current_seq = 0
    current_ack = 0
    total_bytes_received = 0
    file_name = input("File name: ")
    file_name_bytes = file_name.encode("utf-8")
    number_of_packets_received = 0
    s = create_socket()
    send_udp(
        s,
        file_name_bytes,
        current_seq,
        current_ack,
    )

    with open("copy_" + file_name, "wb") as f:
        while True:
            # receiving the file
            packet_received = receive_udp(s)
            payload = extract_payloads(packet_received)
            if not payload:
                continue

            # updating the number of packets received
            number_of_packets_received += 1

            # check if the file transfer is done
            if payload[1] == -1 and payload[0] == b"FIN":
                str_number_of_packets = str(number_of_packets_received)
                send_udp(
                    s,
                    str_number_of_packets.encode("utf-8"),
                    current_seq,
                    -1,
                )
                break

            if (
                payload[1] == current_ack
            ):  # payload{1] is seq number of the packet from server
                current_ack += 1
                f.write(payload[0])
                total_bytes_received += len(payload[0])
                # send ack every 5 packets
                if current_ack % 5 == 0:
                    send_udp(
                        s,
                        b"ACK",
                        current_seq,
                        current_ack,
                    )
            else:
                send_udp(
                    s,
                    b"ACK",
                    current_seq,
                    current_ack,
                )

    s.close()


if __name__ == "__main__":
    main()
