import socket

class UDPEchoServer:
    def __init__(self, host="0.0.0.0", port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((self.host, self.port))
        print(f"UDP Echo Server started at {self.host}:{self.port}")

    def handle_client(self):
        while True:
            message, client_address = self.server_socket.recvfrom(1024)
            print(f"Received message: {message.decode()} from {client_address}")
            self.server_socket.sendto(message, client_address)

if __name__ == "__main__":
    server = UDPEchoServer()
    server.handle_client()
