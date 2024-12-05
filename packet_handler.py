from struct import unpack
import socket
from packet_builder import PacketBuilder

class PacketHandler:
    @staticmethod
    def extract_payloads(packet, src_ip, dst_ip, src_port, dst_port):
        if packet is None:
            return None

        if len(packet) < 36:  # if the packet is not a data packet
            print("Not a data packet")
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

        if udp_fields["source_port"] != src_port or udp_fields["dest_port"] != dst_port:
            return None

        checksum_data = packet[20:]
        computed_checksum = PacketBuilder.checksum(checksum_data)
        if computed_checksum != 0:
            print("Checksum failed")
            return None

        return [packet[36:], udp_fields["seq_number"], udp_fields["ack_number"]]
