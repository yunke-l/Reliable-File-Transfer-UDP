import os
import sys
from time import sleep
import time
from datetime import timedelta
import socket
from struct import pack, unpack
import struct

SERVER_RECV_PORT = 50100
SERVER_SEND_PORT = 50101
CHUNK_SIZE = 1300


def create_socket(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    except socket.error as msg:
        print(
            "Socket could not be created. Error Code : "
            + str(msg[0])
            + " Message "
            + msg[1]
        )
        sys.exit()
    try:
        s.bind(("", port))
    except socket.error as msg:
        print("Can not bind socket. Error Code : " + str(msg[0]) + " Message " + msg[1])
        sys.exit()
    return s


def receive_udp(socket):
    server_socket = socket
    client_info = []
    try:
        while True:
            data, addr = server_socket.recvfrom(65535)
            print("Data length:", len(data))
            udp_header = data[20:28]
            udp_unpack = unpack("!HHHH", udp_header)
            source_port, dest_port, length, checksum = udp_unpack
            if source_port != 3435:
                continue
            client_info.append(addr[0]) # client IP
            client_info.append(source_port) # client port
            payload = data[28:]
            string_payload = payload.decode("utf-8")
            client_info.append(string_payload)
            print(f"Received message from {client_info[0]}:{client_info[1]}")
            return client_info

    except KeyboardInterrupt:
        print("Server shutting down.")


def send_udp(
    passed_socket, payload: bytes, dst_ip, src_ip, dst_port, src_port, seq_number, ack_number
):
    s = passed_socket
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # create udp header
    udp_src_port = src_port
    udp_dst_port = dst_port
    udp_length = 16 + len(payload)
    udp_seq = seq_number
    udp_ack = ack_number
    checksum = 0
    udp_header = pack(
        "!HHHIIH", udp_src_port, udp_dst_port, udp_length, udp_seq, udp_ack, checksum
    )

    # create the IP header
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

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    packet = ip_header + udp_header + payload
    print(f"sending: {seq_number + 1}/{ack_number} from {src_port} "
      f"to {dst_ip}: {dst_port} with length {len(packet)}")
    s.sendto(packet, (dst_ip, dst_port))


def send_file_chunks(socket, content: bytes, chunk_size, src_ip, dst_ip, dst_port, src_port):
    file_chunks = [
        content[i : i + chunk_size] for i in range(0, len(content), chunk_size)
    ]
    num_chunks = len(file_chunks)
    batch_size = 50
    delay = 1

    for i in range(0, num_chunks, batch_size):
        for j in range(i, min(i + batch_size, num_chunks)):  # sequence number
            send_udp(
                socket,
                file_chunks[j],
                src_ip,
                dst_ip,
                dst_port,
                src_port,
                j,
                num_chunks,
            )
        sleep(delay)


def file_exists(filename):
    return os.path.isfile(filename)


def load_file_as_bytes(filename):
    with open(filename, "rb") as file:
        file_content_bytes = file.read()
        return file_content_bytes


def main():
    # asking for arguments
    if len(sys.argv) != 2:
        print("Usage: python3 server.py <IP_address>")
        sys.exit(1)
    server_IP = sys.argv[1]
    #  receiving request for file name
    server_rcv_socket = create_socket(SERVER_RECV_PORT) # receiving socket
    server_rcv_socket.bind((server_IP, SERVER_RECV_PORT))
    server_snd_socket = create_socket(SERVER_SEND_PORT) # sending socket

    # receive the request from the client
    client_info = receive_udp(server_rcv_socket)
    client_IP = client_info[0]
    print(f"Client IP: {client_IP}")
    client_PORT = client_info[1]
    print(f"Client PORT: {client_PORT}")
    filename = client_info[2]
    if not file_exists(filename):
        print("File does not exist! Session terminated.")
        with open("downloadLog.txt", "w") as f:
            f.write("File does not exist!")
        sys.exit(0)

    start_time = time.time()  # record start time

    # load file as bytes
    content_bytes = load_file_as_bytes(filename)
    file_size = len(content_bytes)
    packet_number = file_size // CHUNK_SIZE + 1
    print(f"Size of the transferred file: {file_size} bytes")
    print(f"The number of packets sent from the server: {packet_number}")

    # sending requested file
    sleep(2)
    send_file_chunks(
        server_snd_socket, content_bytes, CHUNK_SIZE, server_IP, client_IP, client_PORT, SERVER_RECV_PORT
    )

    # receiving transferring result
    # server_rcv_socket2 = create_socket(SERVER_RECV_PORT)
    result = receive_udp(server_rcv_socket)
    print(result[0])
    print(result[1])
    result_str = result[2]
    packet_received = int(result_str[7:])
    end_time = time.time()  # record ending time
    time_taken = int(end_time - start_time)
    time_taken_formatted = str(timedelta(seconds=time_taken))
    print(f"Time taken to transfer the file: {time_taken} seconds")


    # write log
    if "success" in result:
        with open("downloadLog.txt", "w") as f:
            f.write(f"Name of the transferred file: {filename}\n")
            f.write(f"Size of the transferred file: {file_size} bytes\n")
            f.write(f"The number of packets sent from the server: {packet_number}\n")
            f.write(f"The number of retransmitted packets from the server: 0\n")
            f.write(
                f"The number of packets received by the client: {packet_received}\n"
            )
            f.write(f"Time taken to transfer the file: {time_taken_formatted}\n")


if __name__ == "__main__":
    main()
