import os
import struct
import socket
import sys


def create_socket():
    try:
        newsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_UDP)
    except socket.error as e:
        print(f'Socket creation failed: {e}')
        sys.exit()
    return newsocket


def calculate_checksum(segment):
    if len(segment) % 2 != 0:
        segment += b'\0'  # Padding if segment length is odd

    checksum = 0
    for i in range(0, len(segment), 2):
        word = (segment[i] << 8) + segment[i + 1]
        checksum += word

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += (checksum >> 16)

    return ~checksum & 0xFFFF


def create_payload(filename):
    if not os.path.exists(filename):
        print(f'File {filename} does not exist')
        return

    with open(filename, 'rb') as file:
        file_data = file.read()

    return file_data


def create_UDP_segment(seq_num, ack_num, payload):
    additional_header = struct.pack('!II', seq_num, ack_num)
    udp_src_port = 12345
    udp_dest_port = 54321
    udp_length = 8 + len(additional_header) + len(payload)
    udp_checksum = 0
    udp_header = struct.pack('!HHHH', udp_src_port, udp_dest_port,
                             udp_length, udp_checksum)
    segment = udp_header + additional_header + payload
    udp_checksum = calculate_checksum(segment)
    udp_header = struct.pack('!HHHH', udp_src_port, udp_dest_port,
                             udp_length, udp_checksum)
    return udp_header + additional_header + payload


def create_IP_header(src_ip, dest_ip):
    ip_version = 4
    ip_header_length = 5
    ip_tos = 0
    ip_total_length = 0
    ip_id = 54321
    ip_frag_offset = 0
    ip_ttl = 255
    ip_protocol = socket.IPPROTO_UDP
    ip_checksum = 0
    ip_src_addr = socket.inet_aton(src_ip)
    ip_dest_addr = socket.inet_aton(dest_ip)
    ip_ihl_ver = (ip_version << 4) + ip_header_length
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos,
                            ip_total_length, ip_id, ip_frag_offset,
                            ip_ttl, ip_protocol, ip_checksum,
                            ip_src_addr, ip_dest_addr)
    return ip_header


def main():
    if len(sys.argv) != 4:
        print('Usage: python3 UDP_client.py <src_ip> <dest_ip> <filename>')
        sys.exit()

    src_ip = sys.argv[1]
    dest_ip = sys.argv[2]
    filename = sys.argv[3]

    payload = create_payload(filename)
    if payload is None:
        sys.exit()

    udp_segment = create_UDP_segment(0, 0, payload)
    ip_header = create_IP_header(src_ip, dest_ip)
    packet = ip_header + udp_segment

    sock = create_socket()
    sock.sendto(packet, (dest_ip, 0))
    sock.close()
    print(f'File {filename} sent to {dest_ip}')


if __name__ == '__main__':
    main()
