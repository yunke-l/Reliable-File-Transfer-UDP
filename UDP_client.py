import socket
import struct
import sys
from struct import pack, unpack
from time import sleep

# CLIENT_IP = "172.31.27.101"
# SERVER_IP = "172.31.31.50"
CLIENT_IP = "127.0.0.1"
SERVER_IP = "127.0.0.1"
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
    return s

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
def create_UDP_header(src_port, dst_port, payload: bytes,
                      seq_number, ack_number):
    udp_src_port = src_port
    udp_dst_port = dst_port
    udp_length = 16 + len(payload)
    checksum = 0
    udp_seq = seq_number
    udp_ack = ack_number
    udp_header = pack("!HHHiiH", udp_src_port, udp_dst_port,
                      udp_length, udp_seq, udp_ack, checksum)
    return udp_header

# receive UDP packets
def receive_udp(passed_socket, ip, port):
    receiving_socket = passed_socket
    try:
        receiving_socket.bind((ip, port))
    except socket.error as msg:
        if msg.errno == 98:  # Address already in use
            pass
        else:
            print("Cannot bind socket. Error Code : " + str(msg[0]) + " Message " + msg[1])
            sys.exit()

    print(f"Listening on port {port}")
    try:
        data, addr = receiving_socket.recvfrom(65535)
    except KeyboardInterrupt:
        print("Shutting down.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

    return {"data": data, "addr": addr}

# extract payloads from packets
def extract_payloads(packet):
    if packet is None:
        return None

    data = packet["data"]
    addr = packet["addr"]
    if len(data) < 36:  # if the packet is not a data packet
        print("Not a data packet")
        return None

    # unpack udp header
    udp_header = data[20:36]
    udp_unpack = unpack("!HHHiiH", udp_header)
    udp_fields = {
        "source_port": udp_unpack[0],
        "dest_port": udp_unpack[1],
        "udp_length": udp_unpack[2],
        "seq_number": udp_unpack[3],
        "ack_number": udp_unpack[4],
        "checksum": udp_unpack[5],
    }

    # unpack the ip header
    ip_header = data[:20]
    ip_unpack = unpack("!BBHHHBBH4s4s", ip_header)
    ip_fields = {
        "ip_ihl_ver": ip_unpack[0],
        "ip_tos": ip_unpack[1],
        "ip_tot_len": ip_unpack[2],
        "ip_id": ip_unpack[3],
        "ip_frag_off": ip_unpack[4],
        "ip_ttl": ip_unpack[5],
        "ip_proto": ip_unpack[6],
        "ip_check": ip_unpack[7],
        "ip_saddr": ip_unpack[8],
        "ip_daddr": ip_unpack[9],
    }

    str_ip_saddr = socket.inet_ntoa(ip_fields["ip_saddr"])  # source ip string
    str_ip_daddr = socket.inet_ntoa(ip_fields["ip_daddr"])  # destination ip string
    print(f"IP: {str_ip_saddr} -> {str_ip_daddr} with packets "
          f"of length {ip_fields['ip_tot_len']}\n")

    # filtering packet: the packet is not from the server or to the client
    if str_ip_saddr != SERVER_IP or str_ip_daddr != CLIENT_IP:
        print('Not from the server or to the client')
        return None

    # filtering packet: in case loopback packet
    if udp_fields["dest_port"] != CLIENT_PORT or udp_fields["source_port"] != SERVER_PORT:
        print('Not from the server port or to the client port')
        return None
    with open('dataTransferAtC.txt', 'a') as f:
        f.write(f"UDP: receiving from {addr[0]}:{udp_fields['source_port']} "
                f"with packets of length {udp_fields['udp_length']+20}\n")
        f.write(f"IP: {str_ip_saddr} -> {str_ip_daddr} "
                f"with packets of length {ip_fields['ip_tot_len']}\n")
        f.write(f"{udp_fields['seq_number']},")

    payload = data[36:]
    print(f"Received packet with sequence number {udp_fields['seq_number']}")

    return [payload, udp_fields["seq_number"], udp_fields["ack_number"]]

def send_udp(passed_socket, payload: bytes, src_ip, dst_ip,
             src_port, dst_port, seq_number, ack_number):
    ip_header = create_IP_header(src_ip, dst_ip, payload)
    udp_header = create_UDP_header(src_port, dst_port,
                                   payload, seq_number, ack_number)

    packet = ip_header + udp_header + payload
    print(f"Sending to {dst_ip}:{dst_port} with length {len(packet)}")
    passed_socket.sendto(packet, (dst_ip, 0))

# def communicate_file_transfer(passed_socket, filename: bytes, src_ip, dst_ip,
#                               src_port, dst_port):
#     ip_header = create_IP_header(src_ip, dst_ip, filename)
#     udp_header = create_UDP_header(src_port, dst_port,
#                                    filename, -1, 0)
#     packet = ip_header + udp_header + filename
#     print(f"Sending to {dst_ip}:{dst_port} with length {len(packet)}")
#     passed_socket.sendto(packet, (dst_ip, 0))
#     filesize_data, addr =   passed_socket.recvfrom(65535)
#     filesize = int(filesize_data.decode("utf-8"))
#     return filesize

def main():
    current_seq = 0
    current_ack = 0
    total_bytes_received = 0
    file_name = input("File name: ")
    file_name_bytes = file_name.encode("utf-8")
    s = create_socket()
    # filesize = communicate_file_transfer(s, file_name_bytes, CLIENT_IP,
    #                                      SERVER_IP, CLIENT_PORT, SERVER_PORT)
    send_udp(s, file_name_bytes, CLIENT_IP, SERVER_IP,
             CLIENT_PORT, SERVER_PORT, current_seq, current_ack)

    with open('copy_' + file_name, 'wb') as f:
        while True:
            # receiving the file
            packet_received = receive_udp(s, CLIENT_IP, CLIENT_PORT)
            payload = extract_payloads(packet_received)
            if not payload:
                continue

            if payload[1] == -1 and payload[0] == b'FIN':
                print("Received end-of-transfer signal")
                send_udp(s,b'FIN', CLIENT_IP, SERVER_IP,
             CLIENT_PORT, SERVER_PORT, current_seq, -1)
                break

            if payload[1] == current_ack:
                current_ack += 1
                f.write(payload[0])
                total_bytes_received += len(payload[0])
                print(f"Received packet {payload[1]}")
                # send ack every 5 packets
                if current_ack % 5 == 0:
                    send_udp(s, b"ACK", CLIENT_IP, SERVER_IP,
                             CLIENT_PORT, SERVER_PORT, current_seq, current_ack)
            else:
                print(f"Received packet {payload[1]} but expected {current_ack + 1}")
                send_udp(s, b"ACK", CLIENT_IP, SERVER_IP,
                         CLIENT_PORT, SERVER_PORT, current_seq, current_ack)


    # result = "success" + str(filesize)
    # received_packets_result = result.encode("utf-8")
    # sleep(2)
    # send_udp(s, received_packets_result, CLIENT_IP, SERVER_IP,
    #          CLIENT_PORT, SERVER_PORT, current_seq, current_ack)

    # print(f"Saved the received file to copy_{file_name}.")
    s.close()

if __name__ == "__main__":
    main()
