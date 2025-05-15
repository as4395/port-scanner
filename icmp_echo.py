import socket
import threading
import time

class HTTPServer:
    def __init__(self, host="0.0.0.0", port=8080):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started at {self.host}:{self.port}")

    def handle_client(self, client_socket):
        request = client_socket.recv(1024)
        print(f"Request received: {request.decode('utf-8')}")
        
        response = self.generate_response()
        client_socket.send(response)
        client_socket.close()

    def generate_response(self):
        content = """
        <html>
            <head><title>Simple HTTP Server</title></head>
            <body>
                <h1>Welcome to the Simple HTTP Server</h1>
                <p>This is a custom HTTP response!</p>
            </body>
        </html>
        """
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Length: {}\r\n"
            "Connection: close\r\n\r\n"
        ).format(len(content)) + content
        return response.encode()

    def start(self):
        while True:
            print("Waiting for connections...")
            client_socket, client_address = self.server_socket.accept()
            print(f"Connection from {client_address}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()

if __name__ == "__main__":
    server = HTTPServer()
    server.start()
