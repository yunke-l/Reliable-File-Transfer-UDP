import threading
import os
import sys
import socket
import struct
import time

CLIENT_IP = '127.0.0.1'
SERVER_IP = '127.0.0.1'
CLIENT_PORT = 3434
SERVER_PORT = 50100
CHUNK_SIZE = 1000  # Adjust the chunk size based on performance

# Track acknowledged chunks
acknowledged = set()
num_chunks = 0

# Function to calculate checksum


def checksum(data):
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

# Function to send UDP packets with sequence numbers and checksums


def send_udp(payload: bytes, seq_num, src_ip, dst_ip, src_port, dst_port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as msg:
        print('Socket could not be created. Error Code:', msg)
        sys.exit()

    # Construct IP header
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # Kernel will fill the correct total length
    ip_id = 54321
    ip_frag_off = 0x4000  # Don't fragment
    ip_ttl = 64
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    # Add sequence number and checksum
    udp_src_port = src_port
    udp_dst_port = dst_port
    udp_length = 8 + len(payload)
    udp_checksum = 0  # Initial checksum is 0

    # Pack sequence number and checksum into the payload
    seq_num_bytes = struct.pack('!I', seq_num)
    checksum_bytes = struct.pack('!H', 0)  # Initial checksum
    full_payload = seq_num_bytes + checksum_bytes + payload

    # Calculate the checksum
    computed_checksum = checksum(full_payload[6:])
    checksum_bytes = struct.pack('!H', computed_checksum)

    # Construct the final payload with the correct checksum
    full_payload = seq_num_bytes + checksum_bytes + payload

    udp_header = struct.pack('!HHHH', udp_src_port, udp_dst_port, udp_length, udp_checksum)
    packet = ip_header + udp_header + full_payload

    # Send the packet
    s.sendto(packet, (dst_ip, dst_port))

# Function to send file in chunks with sequence numbers and checksum


def send_file_chunks(content: bytes, src_ip, dst_ip, src_port, dst_port):
    global num_chunks
    file_chunks = [content[i:i + CHUNK_SIZE] for i in range(0, len(content), CHUNK_SIZE)]
    num_chunks = len(file_chunks)

    for seq_num, chunk in enumerate(file_chunks):
        if seq_num not in acknowledged:
            send_udp(chunk, seq_num, src_ip, dst_ip, src_port, dst_port)
            print(f"Sent chunk {seq_num}")
        time.sleep(0.01)  # Small delay to avoid overwhelming the network

    print("All chunks sent. Waiting for acknowledgments...")

# Function to listen for acknowledgments


def listen_for_acks():
    ack_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    ack_socket.bind((SERVER_IP, SERVER_PORT))
    ack_socket.settimeout(1)

    while True:
        try:
            ack_data, _ = ack_socket.recvfrom(65535)
            ack_seq_num = struct.unpack('!I', ack_data[:4])[0]
            if ack_seq_num < num_chunks:
                acknowledged.add(ack_seq_num)
                print(f"Acknowledged chunk {ack_seq_num}")
        except socket.timeout:
            continue  # Retry listening for acks

# Function to check if the requested file exists


def file_exists(filename):
    return os.path.isfile(filename)

# Function to load a file as bytes


def load_file_as_bytes(filename):
    with open(filename, 'rb') as file:
        file_content_bytes = file.read()
        return file_content_bytes

# Main server function to receive filename and start file transfer


def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    server_socket.bind((SERVER_IP, SERVER_PORT))

    while True:
        print("Waiting for client request...")
        data, addr = server_socket.recvfrom(65535)
        filename = data.decode('utf-8')

        # Check if the file exists
        if not file_exists(filename):
            print(f"File '{filename}' not found.")
            continue

        print(f"File '{filename}' found. Preparing to send...")

        # Load the file content
        content_bytes = load_file_as_bytes(filename)

        # Create threads for sending file chunks and listening for acknowledgments
        send_thread = threading.Thread(target=send_file_chunks, args=(content_bytes, SERVER_IP, addr[0], SERVER_PORT, addr[1]))
        ack_thread = threading.Thread(target=listen_for_acks)

        # Start threads
        send_thread.start()
        ack_thread.start()

        # Wait for sending thread to complete
        send_thread.join()
        print("File transfer complete.")

        # Stop the acknowledgment thread
        ack_thread.join()


if __name__ == "__main__":
    server()
