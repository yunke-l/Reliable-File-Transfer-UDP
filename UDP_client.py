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

def create_UDP_segment():
    file_name = input('Enter the file name: ')
    # udp_src_port = 12345
    udp_dest_port = 7001
    udp_length = 8 + len(file_name.encode())
    udp_checksum = 0
    udp_header = struct.pack('!HHH', udp_dest_port,
                             udp_length, udp_checksum)
    segment = udp_header + file_name.encode()
    udp_checksum = calculate_checksum(segment)
    udp_header = struct.pack('!HHH', udp_dest_port,
                             udp_length, udp_checksum)
    return udp_header + file_name.encode()


def create_IP_header():
    src_ip = '127.0.0.1'  # loopback address
    dest_ip = '127.0.0.1'  # loopback address
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
    udp_segment = create_UDP_segment()
    ip_header = create_IP_header()
    packet = ip_header + udp_segment

    client_socket = create_socket()
    client_socket.sendto(packet, ('127.0.0.1', 0))
    # modifiedMessage, serverAddress = client_socket.recvfrom(65535)
    # print('From the server: ', modifiedMessage.decode())
    client_socket.close()


if __name__ == '__main__':
    main()
