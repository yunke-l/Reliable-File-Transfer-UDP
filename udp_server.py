import os
import time
from datetime import timedelta
from udp_socket import UDPSocket
from packet_builder import PacketBuilder
from packet_handler import PacketHandler

CLIENT_IP = "172.31.21.219"
SERVER_IP = "172.31.21.112"
CLIENT_PORT = 3434
SERVER_PORT = 50100
CHUNK_SIZE = 1300
BATCH_SIZE = 5


class UDPServer:
    def __init__(self, server_ip, client_ip, server_port, client_port):
        self.server_ip = server_ip
        self.client_ip = client_ip
        self.server_port = server_port
        self.client_port = client_port
        self.socket = UDPSocket(server_ip, server_port)
        self.current_seq = 0
        self.current_ack = 0
        self.num_of_packets_sent = 0
        self.num_of_packets_retransmitted = 0
        self.num_of_packets_recv_by_client = ''
        self.file_size = 0
        self.file_transfer_complete = False
        self.timeout = 2
        self.filename = ''

    def send_packet(self, payload, seq_number, ack_number):
        ip_header = PacketBuilder.create_ip_header(self.server_ip, self.client_ip, payload)
        udp_header = PacketBuilder.create_udp_header(
            self.server_port, self.client_port, payload, seq_number, ack_number
        )
        packet = ip_header + udp_header + payload
        self.socket.send_udp(packet, self.client_ip)
        self.num_of_packets_sent += 1

    def listen_for_request(self):
        while True:
            request = self.socket.receive_udp()
            request_payload = PacketHandler.extract_payloads(
                request, self.client_ip, self.server_ip, self.client_port, self.server_port
            )
            if not request_payload:
                continue

            if request_payload[1] == 0 and request_payload[2] == 0:
                print("Received request for file transfer")
                filename_bytes = request_payload[0]
                if not os.path.isfile(filename_bytes.decode("utf-8")):
                    self.send_packet(b"File does not exist.", -1, self.current_ack)
                    print("File does not exist.")
                    self.start_time = time.time()
                    break
                self.filename = filename_bytes.decode("utf-8")
                self.current_seq = request_payload[2]
                self.file_size = os.path.getsize(self.filename)
                self.start_time = time.time()
                break

    def transfer_file(self):
        if not self.filename:
            return
        with open(self.filename, "rb") as file:
            while not self.file_transfer_complete:
                fail_safe_start_time = time.time()
                for i in range(BATCH_SIZE):
                    file.seek((self.current_seq + i) * CHUNK_SIZE)
                    data = file.read(CHUNK_SIZE)
                    if not data:
                        self.send_packet(b"FIN", -1, self.current_ack)
                        return
                    self.send_packet(data, self.current_seq + i, self.current_ack)

                while True:
                    if time.time() - fail_safe_start_time > self.timeout:
                        print(
                            f"Fail-safe timeout of {self.timeout} seconds reached. Retransmitting the batch."
                        )
                        fail_safe_start_time = time.time()
                        break

                    request = self.socket.receive_udp()
                    request_payload = PacketHandler.extract_payloads(
                        request, self.client_ip, self.server_ip, self.client_port, self.server_port
                    )
                    if request_payload:
                        if request_payload[2] == -1:
                            print(f"Client confirmed that {self.filename} is received.")
                            self.num_of_packets_recv_by_client = request_payload[0].decode("utf-8")
                            self.file_transfer_complete = True
                            break

                        if request_payload[2] > self.current_seq:
                            self.current_ack = request_payload[2]

                        if self.current_ack >= self.current_seq + BATCH_SIZE - 1:
                            self.current_seq += BATCH_SIZE
                            break
                    else:
                        for j in range(BATCH_SIZE):
                            file.seek((self.current_seq + j) * CHUNK_SIZE)
                            data = file.read(CHUNK_SIZE)
                            self.send_packet(data, self.current_seq + j, self.current_ack)
                            self.num_of_packets_retransmitted += 1
                            continue

    def write_log(self):
        end_time = time.time()
        time_taken = int(end_time - self.start_time)
        time_taken_formatted = str(timedelta(seconds=time_taken))
        print(f"Time taken to transfer the file: {time_taken} seconds")

        with open('downloadLog.txt', 'w') as f:
            f.write(f"Name of the transferred file: {self.filename}\n")
            f.write(f"Size of the transferred file: {self.file_size} bytes\n")
            f.write(f"The number of packets sent from the server: {self.num_of_packets_sent}\n")
            f.write(f"The number of retransmitted packets from the server: {self.num_of_packets_retransmitted}\n")
            f.write(f"The number of packets received by the client: {self.num_of_packets_recv_by_client}\n")
            f.write(f"Time taken to transfer the file: {time_taken_formatted}\n")

    def run(self):
        self.listen_for_request()
        self.transfer_file()
        self.socket.close_socket()
        self.write_log()


def main():
    server = UDPServer(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT)
    server.run()


if __name__ == "__main__":
    main()
