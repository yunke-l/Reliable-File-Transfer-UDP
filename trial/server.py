import os
import sys
from time import sleep
import socket
from struct import pack, unpack
import struct

CLIENT_IP = '127.0.0.1'
SERVER_IP = '127.0.0.1'

CLIENT_PORT = 3434
SERVER_PORT = 50100


def receive_udp(ip, port, single):
    payloads = []

    try:
        server_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' +
              str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    server_ip = ip
    server_port = port

    try:
        server_socket.bind((server_ip, server_port))
    except socket.error as msg:
        print('Can not bind socket. Error Code : ' +
              str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    print(f"Server listening on {server_ip}:{server_port}")

    try:
        while True:
            data, addr = server_socket.recvfrom(65535)
            print(f"Received message from {addr}")
            print(data.hex())
            print(len(data))
            if (len(data) > 28):
                ip_header = data[0:20]
                print('ip_header:', ip_header.hex())

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
                string_payload = payload.decode('utf-8')
                print(f"Payload:\n{string_payload}")
                return payload
            else:
                num_chunks_info = data[48:52]
                num_chunks = struct.unpack('!I', num_chunks_info)[0]

                index_info = data[52:56]
                index = struct.unpack('!I', index_info)[0]

                payloads.append(payload)
                print(f"received {index}/{num_chunks-1}")
                if len(payloads) >= num_chunks:
                    print(f"Received last chunk woo ho!")
                    return payloads

    except KeyboardInterrupt:
        print('Server shutting down.')
    finally:
        server_socket.close()


def send_udp(payload: bytes, src_ip, dst_ip, src_port, dst_port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' +
              str(msg[0]) + ' Message ' + msg[1])
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
    checksum = 0
    udp_header = pack('!HHHH', udp_src_port,
                      udp_dst_port, udp_length, checksum)

    packet = udp_header + payload

    s.sendto(packet, (dst_ip, dst_port))


def send_file_chunks(content: bytes, chunk_size, src_ip, dst_ip, src_port, dst_port):
    file_chunks = [content[i:i + chunk_size]
                   for i in range(0, len(content), chunk_size)]
    num_chunks = len(file_chunks)

    for i, c in enumerate(file_chunks):
        # first 4 bytes will be used to store i
        indexed_chunk = struct.pack(
            '!I', num_chunks) + struct.pack('!I', i) + c
        send_udp(indexed_chunk, src_ip, dst_ip, src_port, dst_port)


def file_exists(filename):
    return os.path.isfile(filename)


def load_file_as_bytes(filename):
    with open(filename, 'rb') as file:
        file_content_bytes = file.read()
        return file_content_bytes


if __name__ == "__main__":
    filename_bytes = receive_udp(SERVER_IP, SERVER_PORT, True)

    filename = filename_bytes.decode('utf-8')
    if not file_exists(filename):
        print("File not exist system close")
        sys.exit(0)

    content_bytes = load_file_as_bytes(filename)

    sleep(2)

    send_file_chunks(content_bytes, 1000, SERVER_IP, CLIENT_IP, SERVER_PORT,
                     CLIENT_PORT)