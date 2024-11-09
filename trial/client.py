import socket
import struct
import sys
from struct import pack, unpack


CLIENT_IP = '127.0.0.1'
SERVER_IP = '127.0.0.1'

CLIENT_PORT = 3434
SERVER_PORT = 50100


def receive_udp(ip, port, single):
    payloads = []

    try:
        server_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
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
            # print(data.hex())

            # need to skip the first 20 header.
            # Looks like kernal add one additional layer of ip header to package.
            # Unpack IP header
            ip_header = data[20:40]
            iph = unpack('!BBHHHBBH4s4s', ip_header)
            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr = iph
            # print(ip_proto)

            # Unpack UDP header
            udp_header = data[40:48]
            udp_unpack = unpack('!HHHH', udp_header)

            source_port, dest_port, length, checksum = udp_unpack
            # print(f"UDP Source Port: {source_port}, Dest Port: {dest_port}, Length: {length}")

            payload = data[48:]

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
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' +
              str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    # construct UDP header
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = 12345
    ip_frag_off = 0x4000
    ip_ttl = 40
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
                     ip_saddr, ip_daddr)

    # construct UDP header
    udp_src_port = src_port
    udp_dst_port = dst_port
    udp_length = 8 + len(payload)
    checksum = 0
    udp_header = pack('!HHHH', udp_src_port,
                      udp_dst_port, udp_length, checksum)

    packet = ip_header + udp_header + payload

    s.sendto(packet, (dst_ip, dst_port))


def receive_file_chunks(ip, port):
    return receive_udp(ip, port, False)


def save_bytes_to_file(file_bytes, file_name):
    with open(file_name, 'wb') as file:
        file.write(file_bytes)


if __name__ == "__main__":
    file_name = input("File name: ")
    file_name_bytes = file_name.encode('utf-8')
    send_udp(file_name_bytes, CLIENT_IP, SERVER_IP,
             CLIENT_PORT, SERVER_PORT)

    payloads = receive_file_chunks(CLIENT_IP, CLIENT_PORT)

    received_file_bytes = b''.join(payload[8:] for payload in payloads)

    new_file_name = "copy_" + file_name

    save_bytes_to_file(received_file_bytes, new_file_name)

    print(f"Saved the received file to {new_file_name}.")