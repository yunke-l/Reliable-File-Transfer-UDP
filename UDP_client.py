import socket
import struct
import sys
from struct import pack, unpack


CLIENT_SENDING_PORT = 3434
CLIENT_RECEIVING_PORT = 3435
SERVER_PORT = 50100

def create_sending_socket():
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
    return s

def create_receiving_socket():
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
    return s


def receive_udp(socket):
    payloads = []
    client_socket = socket
    try:
        while True:
            data, addr = client_socket.recvfrom(65535)

            if len(data) <= 36:
                print('not a data packet')
                continue


            udp_header = data[20:36]
            udp_unpack = unpack('!HHHIIH', udp_header)
            source_port, dest_port, length, seq_number, ack_number, checksum = udp_unpack
            print(f"receiving from {addr[0]}:{source_port} with packets of length {length}")
            with open('dataTransfer.txt', 'a') as f:
                f.write(f"{seq_number},")

            payload = data[36:]
            payloads.append(payload)
            print(f"received {seq_number}/{ack_number}")

            if len(payloads) >= ack_number:
                print(len(payloads), ack_number)
                print(f"Received last packet, yay!")
                return payloads

    except KeyboardInterrupt:
        print('Shutting down.')


def send_udp(passed_socket, payload: bytes, src_ip, dst_ip, dst_port, src_port):
    s = passed_socket
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # create udp header
    udp_src_port = src_port
    udp_dst_port = dst_port
    udp_length = 8 + len(payload)
    checksum = 0
    udp_header = pack('!HHHH', udp_src_port,
                      udp_dst_port, udp_length, checksum)
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
    print(f"Sending to {dst_ip}:{dst_port} with length {len(packet)}")
    s.sendto(packet, (dst_ip, 0))


def save_bytes_to_file(file_bytes, file_name):
    with open(file_name, 'wb') as file:
        file.write(file_bytes)


def main():
    # asking for arguments
    if len(sys.argv) != 3:
        print("Usage: python3 client.py <source_IP> <destination_IP>")
        sys.exit(1)
    # create a client socket
    client_snd_socket = create_sending_socket()
    client_rcv_socket = create_receiving_socket()

    file_name = input("File name: ")
    file_name_bytes = file_name.encode('utf-8')
    server_IP = sys.argv[2]
    client_IP = sys.argv[1]
    client_rcv_socket.bind((client_IP, CLIENT_RECEIVING_PORT))
    send_udp(client_snd_socket, file_name_bytes, client_IP, server_IP,
             SERVER_PORT, CLIENT_RECEIVING_PORT)

    # listening on the client socket to receive the file
    payloads = receive_udp(client_rcv_socket)

    # make a copy of the received file
    received_file_bytes = b''.join(payload for payload in payloads)
    new_file_name = "copy_" + file_name
    save_bytes_to_file(received_file_bytes, new_file_name)

    # send the success message to the server
    result = "success" + str(len(payloads))
    received_packets_result = result.encode('utf-8')
    send_udp(client_snd_socket, received_packets_result, client_IP, server_IP,
             SERVER_PORT, CLIENT_RECEIVING_PORT)
    print(f"Saved the received file to {new_file_name}.")


if __name__ == "__main__":
    main()