import socket
import threading

class ChatServer:
    def __init__(self, host="0.0.0.0", port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.clients = []

    def handle_client(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024)
                if message:
                    print(f"Message received: {message.decode()}")
                    self.broadcast(message, client_socket)
                else:
                    self.clients.remove(client_socket)
                    client_socket.close()
                    break
            except:
                self.clients.remove(client_socket)
                client_socket.close()
                break

    def broadcast(self, message, sender_socket):
        for client_socket in self.clients:
            if client_socket != sender_socket:
                client_socket.send(message)

    def start(self):
        while True:
            print("Waiting for clients...")
            client_socket, client_address = self.server_socket.accept()
            self.clients.append(client_socket)
            print(f"New connection from {client_address}")
            threading.Thread(target=self.handle_client, args=(client_socket
