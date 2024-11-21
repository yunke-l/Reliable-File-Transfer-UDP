import socket
import struct
import sys
from struct import pack, unpack
from time import sleep


CLIENT_IP = "172.31.27.101"
SERVER_IP = "172.31.31.50"

CLIENT_PORT = 3434
SERVER_PORT = 50100


def receive_udp(ip, port):
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
            if len(data) < 36: # if the packet is not a data packet,
                print('nah')
                continue

            # unpack udp header
            udp_header = data[20:36]
            udp_unpack = unpack('!HHHIIH', udp_header)
            source_port, dest_port, udp_length, seq_number, ack_number, checksum = udp_unpack

            # unpack the ip header
            ip_header = data[:20]
            ip_unpack = unpack('!BBHHHBBH4s4s', ip_header)
            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr = ip_unpack

            str_ip_saddr = socket.inet_ntoa(ip_saddr)
            str_ip_daddr = socket.inet_ntoa(ip_daddr)
            print(f"IP: {str_ip_saddr} -> {str_ip_daddr} with packets of length {ip_tot_len}\n")
            if str_ip_saddr != SERVER_IP or str_ip_daddr != CLIENT_IP: # if the packet is not from the server or to the client,
                print('nahnah')
                continue

            with open('dataTransferAtC.txt', 'a') as f:
                f.write(f"UDP: receiving from {addr[0]}:{source_port} with packets of length {udp_length+20}\n")
                f.write(f"IP: {str_ip_saddr} -> {str_ip_daddr} with packets of length {ip_tot_len}\n")
                f.write(f"{seq_number},")

            payload = data[36:]
            payloads.append(payload)
            print(f"received {seq_number}/{ack_number}")

            if len(payloads) >= ack_number:
                print(len(payloads), ack_number)
                print(f"Received last packet, yay!")

                return payloads

    except KeyboardInterrupt:
        print('Server shutting down.')
    finally:
        server_socket.close()


def send_udp(payload: bytes, src_ip, dst_ip, src_port, dst_port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' +
              str(msg[0]) + ' Message ' + msg[1])
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

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    # construct UDP header
    udp_src_port = src_port
    udp_dst_port = dst_port
    udp_length = 8 + len(payload)
    checksum = 0
    udp_header = pack('!HHHH', udp_src_port,
                      udp_dst_port, udp_length, checksum)

    packet = ip_header + udp_header + payload
    print(f"Sending to {dst_ip}:{dst_port} with length {len(packet)}")
    s.sendto(packet, (dst_ip, 0))


def save_bytes_to_file(file_bytes, file_name):
    with open(file_name, 'wb') as file:
        file.write(file_bytes)
7

if __name__ == "__main__":
    file_name = input("File name: ")
    file_name_bytes = file_name.encode('utf-8')
    send_udp(file_name_bytes, CLIENT_IP, SERVER_IP,
             CLIENT_PORT, SERVER_PORT)

    payloads = receive_udp(CLIENT_IP, CLIENT_PORT)
    result = "success" + str(len(payloads))
    received_packets_result = result.encode('utf-8')

    received_file_bytes = b''.join(payload for payload in payloads)

    new_file_name = "copy_" + file_name

    save_bytes_to_file(received_file_bytes, new_file_name)
    sleep(2)
    send_udp(received_packets_result, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)

    print(f"Saved the received file to {new_file_name}.")
