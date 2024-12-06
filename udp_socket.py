import socket
import sys

class UDPSocket:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.socket = self.create_socket()

    def create_socket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except socket.error as msg:
            print(f"Socket could not be created. Error Code : {msg[0]} Message {msg[1]}")
            sys.exit()
        try:
            s.settimeout(0.25)
            s.bind((self.ip, self.port))
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
        except socket.timeout:
            return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None
        return data

    def close_socket(self):
        self.socket.close()