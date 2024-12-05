from struct import pack
import socket

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
        udp_header = pack("!HHHiiH", src_port, dst_port, udp_length, seq_number, ack_number, checksum_zero)
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
