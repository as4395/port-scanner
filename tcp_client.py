import socket

class TCPFileClient:
    def __init__(self, server_host="localhost", server_port=12345):
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send_file(self, filename):
        self.client_socket.connect((self.server_host, self.server_port))
        with open(filename, "rb") as file:
            while chunk := file.read(1024):
                self.client_socket.send(chunk)
        print("File sent successfully!")
        self.client_socket.close()

if __name__ == "__main__":
    client = TCPFileClient()
    filename = input("Enter filename to send: ")
    client.send_file(filename)
