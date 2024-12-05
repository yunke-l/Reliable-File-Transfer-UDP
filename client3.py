import socket
import struct
import sys
from struct import pack, unpack

CLIENT_IP = "172.31.21.219"
SERVER_IP = "172.31.21.112"
CLIENT_PORT = 3434
SERVER_PORT = 50100


class UDPSocket:
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.socket = self.create_socket()

    def create_socket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except socket.error as msg:
            print(f"Socket could not be created. Error Code : {msg[0]} Message {msg[1]}")
            sys.exit()
        try:
            s.bind((self.client_ip, self.client_port))
        except socket.error as msg:
            print(f"Bind failed. Error: {msg[0]}: {msg[1]}")
            sys.exit()
        return s

    def send_udp(self, packet, dst_ip):
        self.socket.sendto(packet, (dst_ip, 0))

    def receive_udp(self):
        try:
            data = self.socket.recv(65535)
        except KeyboardInterrupt:
            print("Shutting down.")
            return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None
        return data

    def close_socket(self):
        self.socket.close()


class PacketBuilder:
    @staticmethod
    def checksum(data):
        if len(data) % 2 != 0:
            data += b"\x00"
        res = sum(int.from_bytes(data[i:i + 2], byteorder="big") for i in range(0, len(data), 2))
        res = (res >> 16) + (res & 0xFFFF)
        res = res + (res >> 16)
        return (~res) & 0xFFFF

    @staticmethod
    def create_ip_header(src_ip, dst_ip, payload):
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

        return pack(
            "!BBHHHBBH4s4s",
            ip_ihl_ver,
            ip_tos,
            ip_tot_len,
            ip_id,
            ip_frag_off,
            ip_ttl,
            ip_proto,
            ip_check,
            ip_saddr,
            ip_daddr,
        )

    @staticmethod
    def create_udp_header(src_port, dst_port, payload, seq_number, ack_number):
        udp_length = 16 + len(payload)
        checksum_zero = 0
        udp_header = pack(
            "!HHHiiH", src_port, dst_port, udp_length, seq_number, ack_number, checksum_zero
        )
        checksum_data = udp_header + payload
        computed_checksum = PacketBuilder.checksum(checksum_data)
        return pack(
            "!HHHiiH",
            src_port,
            dst_port,
            udp_length,
            seq_number,
            ack_number,
            computed_checksum,
        )


class PacketHandler:
    @staticmethod
    def extract_payloads(packet, src_ip, dst_ip, src_port, dst_port):
        if packet is None:
            return None

        if len(packet) < 36:  # if the packet is not a data packet
            return None

        udp_header = packet[20:36]
        udp_unpack = unpack("!HHHiiH", udp_header)
        udp_fields = {
            "source_port": udp_unpack[0],
            "dest_port": udp_unpack[1],
            "seq_number": udp_unpack[3],
            "ack_number": udp_unpack[4],
            "checksum": udp_unpack[5],
        }

        ip_header = packet[:20]
        ip_unpack = unpack("!BBHHHBBH4s4s", ip_header)
        ip_fields = {
            "ip_saddr": ip_unpack[8],
            "ip_daddr": ip_unpack[9],
        }

        str_ip_saddr = socket.inet_ntoa(ip_fields["ip_saddr"])
        str_ip_daddr = socket.inet_ntoa(ip_fields["ip_daddr"])

        if str_ip_saddr != src_ip or str_ip_daddr != dst_ip:
            return None

        if udp_fields["dest_port"] != dst_port or udp_fields["source_port"] != src_port:
            return None

        checksum_data = packet[20:]
        computed_checksum = PacketBuilder.checksum(checksum_data)
        if computed_checksum != 0:
            print("Checksum failed")
            return None

        return [packet[36:], udp_fields["seq_number"], udp_fields["ack_number"]]


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

    def send_packet(self, payload, seq_number, ack_number):
        ip_header = PacketBuilder.create_ip_header(self.client_ip, self.server_ip, payload)
        udp_header = PacketBuilder.create_udp_header(
            self.client_port, self.server_port, payload, seq_number, ack_number
        )
        packet = ip_header + udp_header + payload
        self.socket.send_udp(packet, self.server_ip)

    def receive_file(self, file_name):
        self.send_packet(file_name.encode("utf-8"), self.current_seq, self.current_ack)
        with open("copy_" + file_name, "wb") as f:
            while True:
                packet_received = self.socket.receive_udp()
                payload = PacketHandler.extract_payloads(
                    packet_received, self.server_ip, self.client_ip, self.server_port, self.client_port
                )
                if not payload:
                    continue

                self.number_of_packets_received += 1

                if payload[1] == -1 and payload[0] == b"FIN":
                    str_number_of_packets = str(self.number_of_packets_received)
                    self.send_packet(str_number_of_packets.encode("utf-8"), self.current_seq, -1)
                    break

                if payload[1] == self.current_ack:
                    self.current_ack += 1
                    f.write(payload[0])
                    self.total_bytes_received += len(payload[0])
                    if self.current_ack % 5 == 0:
                        self.send_packet(b"ACK", self.current_seq, self.current_ack)
                else:
                    self.send_packet(b"ACK", self.current_seq, self.current_ack)

        self.socket.close_socket()


def main():
    client = UDPClient(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
    file_name = input("File name: ")
    client.receive_file(file_name)


if __name__ == "__main__":
    main()
