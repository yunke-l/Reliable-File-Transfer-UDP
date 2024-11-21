import os
import sys
from time import sleep
import time
from datetime import timedelta
import socket
from struct import pack, unpack
import struct

CLIENT_IP = "172.31.27.101"
SERVER_IP = "172.31.31.50"

CLIENT_PORT = 3434
SERVER_PORT = 50100

CHUNK_SIZE = 1300


def receive_udp(ip, port):
    try:
        server_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP
        )
    except socket.error as msg:
        print(
            "Socket could not be created. Error Code : "
            + str(msg[0])
            + " Message "
            + msg[1]
        )
        sys.exit()

    server_ip = ip
    server_port = port

    try:
        server_socket.bind((server_ip, server_port))
    except socket.error as msg:
        print("Can not bind socket. Error Code : " + str(msg[0]) + " Message " + msg[1])
        sys.exit()

    print(f"Server listening on {server_ip}:{server_port}")

    try:
        while True:
            data, addr = server_socket.recvfrom(65535)
            if len(data) < 28:  # if the packet is not a data packet,
                print('nah')
                continue
            # unpack udp header
            udp_header = data[20:28]
            udp_unpack = unpack('!HHHH', udp_header)
            source_port, dest_port, udp_length, checksum = udp_unpack

            # unpack the ip header
            ip_header = data[:20]
            ip_unpack = unpack('!BBHHHBBH4s4s', ip_header)
            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr = ip_unpack

            str_ip_saddr = socket.inet_ntoa(ip_saddr)
            str_ip_daddr = socket.inet_ntoa(ip_daddr)
            print(f"IP: {str_ip_saddr} -> {str_ip_daddr} with packets of length {ip_tot_len}\n")
            if str_ip_saddr != CLIENT_IP or str_ip_daddr != SERVER_IP:  # if the packet is not from the client or to the server,
                print('nahnah')
                continue

            payload = data[28:]
            string_payload = payload.decode("utf-8")
            with open('dataTransferAtS.txt', 'a') as f:
                f.write(f"IP: {str_ip_saddr} -> {str_ip_daddr} with packets of length {ip_tot_len}\n")
                f.write(f"UDP: receiving from {addr[0]}:{source_port} with packets of length {udp_length+20}\n")
                f.write(f'message: {string_payload}\n\n')

            print(f"Payload:\n{string_payload}")
            return payload

    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()


def send_udp(
    payload: bytes, src_ip, dst_ip, src_port, dst_port, seq_number, ack_number
):
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

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id,
                            ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    # construct UDP header
    udp_src_port = src_port
    udp_dst_port = dst_port
    udp_length = 16 + len(payload)
    udp_seq = seq_number
    udp_ack = ack_number
    checksum = 0
    udp_header = pack(
        "!HHHIIH", udp_src_port, udp_dst_port, udp_length, udp_seq, udp_ack, checksum
    )

    packet = ip_header + udp_header + payload
    print(f"sending: {seq_number+1}/{ack_number}")
    s.sendto(packet, (dst_ip, dst_port))


def send_file_chunks(content: bytes, chunk_size, src_ip, dst_ip, src_port, dst_port):
    file_chunks = [
        content[i : i + chunk_size] for i in range(0, len(content), chunk_size)
    ]
    num_chunks = len(file_chunks)
    batch_size = 50
    delay = 1

    for i in range(0, num_chunks, batch_size):
        for j in range(i, min(i + batch_size, num_chunks)):
            send_udp(
                file_chunks[j],
                src_ip,
                dst_ip,
                src_port,
                dst_port,
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


if __name__ == "__main__":
    #  receiving request for file name
    filename_bytes = receive_udp(SERVER_IP, SERVER_PORT)
    filename = filename_bytes.decode("utf-8")
    if not file_exists(filename):
        print("File not exist system close")
        with open("downloadLog.txt", "w") as f:
            f.write("File does not exist!")
        sys.exit(0)
    start_time = time.time()  # record start time

    # load file as bytes
    content_bytes = load_file_as_bytes(filename)
    file_size = len(content_bytes)
    packet_number = file_size // CHUNK_SIZE + 1

    # sending requested file
    sleep(2)
    send_file_chunks(
        content_bytes, CHUNK_SIZE, SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT
    )

    # receiving transferring result
    result = receive_udp(SERVER_IP, SERVER_PORT)
    end_time = time.time()  # record end time
    time_taken = int(end_time - start_time)
    time_taken_formatted = str(timedelta(seconds=time_taken))
    print(f"Time taken to transfer the file: {time_taken} seconds")
    result_str = result.decode("utf-8")
    packet_received = int(result_str[7:])
    print(result_str)

    # write log
    if 'success' in result_str:
        with open('downloadLog.txt', 'w') as f:
            f.write(f"Name of the transferred file: {filename}\n")
            f.write(f"Size of the transferred file: {file_size} bytes\n")
            f.write(f"The number of packets sent from the server: {packet_number}\n")
            f.write(f"The number of retransmitted packets from the server: 0\n")
            f.write(f"The number of packets received by the client: {packet_received}\n")
            f.write(f"Time taken to transfer the file: {time_taken_formatted}\n")
