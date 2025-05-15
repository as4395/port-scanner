import socket

class TCPFileServer:
    def __init__(self, host="0.0.0.0", port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        print(f"File Transfer Server started at {self.host}:{self.port}")

    def handle_client(self, client_socket):
        print("Waiting for file...")
        with open("received_file.txt", "wb") as file:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                file.write(data)
            print("File received successfully!")

        client_socket.close()

    def start(self):
        while True:
            print("Waiting for a connection...")
            client_socket, client_address = self.server_socket.accept()
            print(f"Connection established with {client_address}")
            self.handle_client(client_socket)

if __name__ == "__main__":
    server = TCPFileServer()
    server.start()
