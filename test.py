import socket

def test_bind(ip, port):
    try:
        # Create a UDP socket
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Try to bind to the provided IP and port
        test_socket.bind((ip, port))
        print(f"Successfully bound to IP '{ip}' and port '{port}'")

        # Close the socket after testing
        test_socket.close()
        return True
    except socket.gaierror as e:
        print(f"Address-related error while binding to IP '{ip}' and port '{port}': {e}")
        return False
    except OSError as e:
        print(f"OS error while binding to IP '{ip}' and port '{port}': {e}")
        return False
    except Exception as e:
        print(f"Unexpected error while binding to IP '{ip}' and port '{port}': {e}")
        return False

if __name__ == "__main__":
    # Test cases with different IPs and ports
    test_cases = [
        ("127.0.0.1", 5005),       # Localhost with a common port
        ("0.0.0.0", 6000),         # Bind to all available interfaces
        ("172.31.21.219", 3434),     # Example private IP (may fail if not available)
        ("", 8000),                # Bind to all interfaces (equivalent to "0.0.0.0")
        ("invalid_ip", 9000),      # Invalid IP address
    ]

    for ip, port in test_cases:
        print(f"Testing binding to IP '{ip}' and port '{port}'...")
        result = test_bind(ip, port)
        if result:
            print(f"Test passed for IP '{ip}' and port '{port}'\n")
        else:
            print(f"Test failed for IP '{ip}' and port '{port}'\n")
