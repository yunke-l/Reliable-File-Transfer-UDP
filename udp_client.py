import time
from udp_socket import UDPSocket
from packet_builder import PacketBuilder
from packet_handler import PacketHandler

CLIENT_IP = "172.31.21.219"
SERVER_IP = "172.31.21.112"
CLIENT_PORT = 3434
SERVER_PORT = 50100
CHUNK_SIZE = 1300
BATCH_SIZE = 5


class UDPClient:
    def __init__(self, client_ip, server_ip, client_port, server_port):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.socket = UDPSocket(client_ip, client_port)
        self.current_seq = 0
        self.current_ack = 0
        self.total_bytes_received = 0
        self.number_of_packets_received = 0
        self.file_transfer_complete = False
        self.file_name = ""

    def send_packet(self, payload, seq_number, ack_number):
        ip_header = PacketBuilder.create_ip_header(self.client_ip, self.server_ip, payload)
        udp_header = PacketBuilder.create_udp_header(
            self.client_port, self.server_port, payload, seq_number, ack_number
        )
        packet = ip_header + udp_header + payload
        self.socket.send_udp(packet, self.server_ip)

    def send_request(self):
        self.file_name = input("File name: ")
        self.send_packet(self.file_name.encode("utf-8"), self.current_seq, self.current_ack)


    def receive_file(self):

        with open("copy_" + self.file_name, "wb") as f:
            while not self.file_transfer_complete:
                packet_received = self.socket.receive_udp()
                payload = PacketHandler.extract_payloads(
                    packet_received, self.server_ip, self.client_ip, self.server_port, self.client_port
                )
                if not payload:
                    continue

                self.number_of_packets_received += 1

                if payload[1] == -1 and payload[0] == b"File does not exist.":
                    print("File does not exist.")
                    break

                if payload[1] == -1 and payload[0] == b"FIN":
                    print("File transfer complete: sent: " + str(self.number_of_packets_received))
                    str_number_of_packets = str(self.number_of_packets_received)
                    self.send_packet(str_number_of_packets.encode("utf-8"), self.current_seq, -1)
                    self.file_transfer_complete = True
                    break

                if payload[1] == self.current_ack:
                    self.current_ack += 1
                    f.write(payload[0])
                    self.total_bytes_received += len(payload[0])
                    if self.current_ack % BATCH_SIZE == 0:
                        self.send_packet(b"ACK", self.current_seq, self.current_ack)
                else:
                    self.send_packet(b"ACK", self.current_seq, self.current_ack)

    def run(self):
        self.send_request()
        self.receive_file()
        self.socket.close_socket()


def main():
    client = UDPClient(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
    client.run()


if __name__ == "__main__":
    main()
