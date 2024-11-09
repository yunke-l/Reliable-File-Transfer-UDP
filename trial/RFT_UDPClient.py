import threading
import socket
import struct
import sys
import time

CLIENT_IP = '127.0.0.1'
SERVER_IP = '127.0.0.1'
CLIENT_PORT = 3434
SERVER_PORT = 50100
BUFFER_SIZE = 1024  # Can be adjusted

# Shared variable to track received payloads
received_chunks = {}
expected_seq = 0  # Shared variable for the expected sequence number

# Function to calculate checksum


def checksum(data):
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

# Function to send the initial file request and then send acknowledgments


def send_request_and_acks(filename):
    # Send the initial file request
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        # Construct and send file request
        file_request = filename.encode('utf-8')
        ip_header, udp_header = create_headers(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, file_request)
        client_socket.sendto(ip_header + udp_header + file_request, (SERVER_IP, SERVER_PORT))
        print("File request sent.")

        # Start sending acknowledgments for received chunks
        while True:
            # Send cumulative acknowledgment
            ack = struct.pack('!I', expected_seq)
            client_socket.sendto(ack, (SERVER_IP, SERVER_PORT))
            time.sleep(0.5)  # Small delay to avoid sending too many acks

    except KeyboardInterrupt:
        print("Acknowledgment sending stopped by user.")
    finally:
        client_socket.close()

# Function to create IP and UDP headers


def create_headers(src_ip, dst_ip, src_port, dst_port, payload):
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # Kernel will fill the correct total length
    ip_id = 12345
    ip_frag_off = 0x4000  # Don't fragment
    ip_ttl = 64
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    # Construct UDP header
    udp_src_port = src_port
    udp_dst_port = dst_port
    udp_length = 8 + len(payload)
    udp_checksum = 0
    udp_header = struct.pack('!HHHH', udp_src_port, udp_dst_port, udp_length, udp_checksum)
    
    return ip_header, udp_header

# Function to receive data packets


def receive_data():
    global expected_seq
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    client_socket.bind((CLIENT_IP, CLIENT_PORT))
    client_socket.settimeout(2)

    while True:
        try:
            data, addr = client_socket.recvfrom(65535)
            ip_header = data[:20]
            udp_header = data[20:28]
            payload = data[28:]

            # Extract sequence number, checksum, and file data
            seq_num, recv_checksum = struct.unpack('!I H', payload[:6])
            file_data = payload[6:]

            # Calculate checksum for received data
            computed_checksum = checksum(payload[6:])

            # Check if the packet is valid (correct checksum and sequence number)
            if recv_checksum == computed_checksum and seq_num == expected_seq:
                received_chunks[seq_num] = file_data
                print(f"Received packet with sequence {seq_num}")
                expected_seq += 1
            else:
                print(f"Checksum or sequence number mismatch for seq {seq_num}")

        except socket.timeout:
            print(f"Timeout occurred, requesting retransmission for seq {expected_seq}")

# Function to save received file chunks to a file


def save_received_file(filename):
    with open("copy_" + filename, 'wb') as file:
        for i in sorted(received_chunks):
            file.write(received_chunks[i])
    print(f"File saved as copy_{filename}")


if __name__ == "__main__":
    filename = input("File name: ")

    # Create threads for sending requests/acks and receiving data
    request_thread = threading.Thread(target=send_request_and_acks, args=(filename,))
    receive_thread = threading.Thread(target=receive_data)

    # Start both threads
    request_thread.start()
    receive_thread.start()

    # Wait for both threads to complete
    receive_thread.join()
    save_received_file(filename)
