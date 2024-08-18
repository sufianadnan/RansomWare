import socket

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def udp_server():
    ip = get_ip_address()
    port = 12345
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', port))
    print(f"Listening for broadcast messages on port {port}")

    while True:
        data, addr = server_socket.recvfrom(1024)
        print(f"Received message: {data} from {addr}")
        if data == b'DISCOVER_BACKEND':
            server_socket.sendto(ip.encode('utf-8'), addr)

if __name__ == "__main__":
    udp_server()
