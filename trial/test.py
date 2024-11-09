import socket

try:
    # Test IPPROTO_IP
    test_socket_ip = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    test_socket_ip.close()
    print("Raw socket with IPPROTO_IP is supported.")

except OSError as e:
    print(f"Raw socket with IPPROTO_IP failed: {e}")

try:
    # Test IPPROTO_UDP
    test_socket_udp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    test_socket_udp.close()
    print("Raw socket with IPPROTO_UDP is supported.")

except OSError as e:
    print(f"Raw socket with IPPROTO_UDP failed: {e}")
