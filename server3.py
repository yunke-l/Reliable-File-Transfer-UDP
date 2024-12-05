import os
import sys
from time import sleep
import time
from datetime import timedelta
import socket
from struct import pack, unpack
import struct

CLIENT_IP = "172.31.21.219"
SERVER_IP = "172.31.21.112"

# CLIENT_IP = "127.0.0.1"
# SERVER_IP = "127.0.0.1"

CLIENT_PORT = 3434
SERVER_PORT = 50100

CHUNK_SIZE = 1300
BATCH_SIZE = 5


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
        s.bind((SERVER_IP, SERVER_PORT))
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
    # print(f"Listening on port {port}")
    try:
        data = receiving_socket.recv(65535)
    except KeyboardInterrupt:
        print("Shutting down.")
        return None
    except socket.timeout:
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
    if len(data) < 36:  # if the packet is not a data packet,
        print("Not a data packet")
        return None

    # unpack udp header
    udp_header = data[20:36]
    udp_unpack = unpack("!HHHiiH", udp_header)
    udp_fields = {
        "source_port": udp_unpack[0],
        "dest_port": udp_unpack[1],
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
    str_ip_saddr = socket.inet_ntoa(ip_fields["ip_saddr"])
    str_ip_daddr = socket.inet_ntoa(ip_fields["ip_daddr"])
    # if the packet is not from the server or to the client,
    if str_ip_saddr != CLIENT_IP or str_ip_daddr != SERVER_IP:
        return None
    # if the packet is not from the client port or to the server port,
    if (
        udp_fields["source_port"] != CLIENT_PORT
        or udp_fields["dest_port"] != SERVER_PORT
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
    src_ip=SERVER_IP,
    dst_ip=CLIENT_IP,
    src_port=SERVER_PORT,
    dst_port=CLIENT_PORT,
):

    ip_header = create_IP_header(src_ip, dst_ip, payload)
    udp_header = create_UDP_header(src_port, dst_port, payload, seq_number, ack_number)

    packet = ip_header + udp_header + payload
    passed_socket.sendto(packet, (dst_ip, 0))


def file_exists(filename):
    return os.path.isfile(filename)



def main():
    num_of_packets_sent = 0 # number of packets sent from the server
    num_of_packets_retransmitted = 0 # number of retransmitted packets from the server
    num_of_packets_recv_by_client = '' # number of packets received by the client
    file_size = 0
    current_seq = 0
    current_ack = 0
    s = create_socket()
    s.settimeout(0.25)
    filename = ""
    file_transfer_complete = False

    while True:
        # listening for the client request
        request = receive_udp(s)
        request_payload = extract_payloads(request)
        if not request_payload:
            continue

        # receiving request for file transfer when seq_number is 0 and ack_number is 0
        if request_payload[1] == 0 and request_payload[2] == 0:
            print("Received request for file transfer")
            filename_bytes = request_payload[0]
            filename = filename_bytes.decode("utf-8")
            current_seq = request_payload[2]
            if not file_exists(filename):
                print("File does not exist. System closing.")
                continue
            if file_exists(filename):
                file_size = os.path.getsize(filename)
                start_time = (
                    time.time()
                )  # record start time after receiving the request
                break  # Break out of the request listening loop

    # Open file and send in chunks
    with open(filename, "rb") as file:
        while not file_transfer_complete:
            # Start the timer for the entire batch
            fail_safe_start_time = time.time()
            timeout = 2  # Fail-safe timeout in seconds

            # Send a batch of packets
            for i in range(BATCH_SIZE):
                file.seek((current_seq + i) * CHUNK_SIZE)
                data = file.read(CHUNK_SIZE)
                if not data:
                    # Send FIN message to indicate end of file
                    send_udp(
                        s,
                        b"FIN",
                        -1,
                        current_ack,
                    )
                    num_of_packets_sent += 1
                    break

                # Send packet
                send_udp(
                    s,
                    data,
                    current_seq + i,
                    current_ack,
                )
                num_of_packets_sent += 1


            # Wait for ACK for the entire batch with a fail-safe mechanism
            while True:
                # Check if the fail-safe timeout has been reached
                if time.time() - fail_safe_start_time > timeout:
                    print(
                        f"Fail-safe timeout of {timeout} seconds reached. Retransmitting the batch."
                    )
                    # Restart the fail-safe timer
                    fail_safe_start_time = time.time()
                    break

                request = receive_udp(s)
                request_payload = extract_payloads(request)
                if request_payload:
                    if request_payload[2] == -1:
                        # If the client confirms receipt of all packets
                        print(f"Client confirmed that {filename} is received.")
                        num_of_packets_recv_by_client = request_payload[0].decode("utf-8")
                        file_transfer_complete = True
                        break
                    # Update the current ACK number
                    if request_payload[2] > current_seq:
                        current_ack = request_payload[2]

                    # If we receive ACK for the entire batch (last sequence number in the batch)
                    if current_ack >= current_seq + BATCH_SIZE - 1:
                        # Update the sequence number to reflect the packets sent in the batch
                        current_seq += BATCH_SIZE
                        break
                else:
                    for j in range(BATCH_SIZE):
                        file.seek((current_seq + j) * CHUNK_SIZE)
                        data = file.read(CHUNK_SIZE)
                        send_udp(
                            s,
                            data,
                            current_seq + j,
                            current_ack,
                        )
                        num_of_packets_sent += 1
                        num_of_packets_retransmitted += 1
                        continue

    end_time = time.time()  # record end time
    time_taken = int(end_time - start_time)
    time_taken_formatted = str(timedelta(seconds=time_taken))
    print(f"Time taken to transfer the file: {time_taken} seconds")
    # Close the socket after file transfer is complete
    s.close()

    # write log file of the transfer
    with open('downloadLog.txt', 'w') as f:
        f.write(f"Name of the transferred file: {filename}\n")
        f.write(f"Size of the transferred file: {file_size} bytes\n")
        f.write(f"The number of packets sent from the server: {num_of_packets_sent}\n")
        f.write(f"The number of retransmitted packets from the server: {num_of_packets_retransmitted}\n")
        f.write(f"The number of packets received by the client: {num_of_packets_recv_by_client}\n")
        f.write(f"Time taken to transfer the file: {time_taken_formatted}\n")



if __name__ == "__main__":
    main()
