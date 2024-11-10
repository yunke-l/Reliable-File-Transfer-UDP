import os
import sys
from time import sleep
import time
from datetime import timedelta
import socket
from struct import pack, unpack
import struct

CLIENT_IP = "127.0.0.1"
SERVER_IP = "127.0.0.1"

CLIENT_PORT = 3434
SERVER_PORT = 50100

CHUNK_SIZE = 1300


def receive_udp(ip, port, single):
    payloads = []

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
            print(f"Received message from {addr}")
            print(data.hex())
            print(len(data))
            if len(data) > 28:
                ip_header = data[0:20]
                print("ip_header:", ip_header.hex())

            # need to skip the first 20 header.
            # Looks like kernal add one additional layer of ip header to package.
            # Unpack IP header
            # ip_header = data[20:40]
            # iph = unpack('!BBHHHBBH4s4s', ip_header)
            # ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr = iph
            # # print(ip_proto)

            # # Unpack UDP header
            # udp_header = data[40:48]
            # udp_unpack = unpack('!HHHH', udp_header)

            # source_port, dest_port, length, checksum = udp_unpack
            # # print(f"UDP Source Port: {source_port}, Dest Port: {dest_port}, Length: {length}")

            payload = data[28:]

            if single:
                string_payload = payload.decode("utf-8")
                print(f"Payload:\n{string_payload}")
                return payload
            else:
                num_chunks_info = data[48:52]
                num_chunks = struct.unpack("!I", num_chunks_info)[0]

                index_info = data[52:56]
                index = struct.unpack("!I", index_info)[0]

                payloads.append(payload)
                print(f"received {index}/{num_chunks-1}")
                if len(payloads) >= num_chunks:
                    print(f"Received last chunk woo ho!")
                    return payloads

    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()


def send_udp(
    payload: bytes, src_ip, dst_ip, src_port, dst_port, seq_number, ack_number
):
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

    # construct UDP header
    # ip_ihl = 5
    # ip_ver = 4
    # ip_tos = 0
    # ip_tot_len = 0  # kernel will fill the correct total length
    # ip_id = 12345
    # ip_frag_off = 0x4000
    # ip_ttl = 40
    # ip_proto = socket.IPPROTO_UDP
    # ip_check = 0
    # ip_saddr = socket.inet_aton(src_ip)
    # ip_daddr = socket.inet_aton(dst_ip)
    # ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
    #                  ip_saddr, ip_daddr)

    # construct UDP header
    udp_src_port = src_port
    udp_dst_port = dst_port
    udp_length = 8 + len(payload)
    udp_seq = seq_number
    udp_ack = ack_number
    checksum = 0
    udp_header = pack(
        "!HHHIIH", udp_src_port, udp_dst_port, udp_length, udp_seq, udp_ack, checksum
    )

    packet = udp_header + payload
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
    filename_bytes = receive_udp(SERVER_IP, SERVER_PORT, True)
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
    result = receive_udp(SERVER_IP, SERVER_PORT, True)
    end_time = time.time()  # record end time
    time_taken = end_time - start_time
    time_taken_formatted = str(timedelta(seconds=time_taken))
    print(f"Time taken to transfer the file: {end_time - start_time} seconds")
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
            f.write(f"Time taken to transfer the file: {end_time - start_time} seconds\n")
