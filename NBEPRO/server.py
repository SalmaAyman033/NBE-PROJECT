import os
import socket
import threading
import base64
from Crypto.Cipher import AES

# Define AES encryption parameters
key = b"TheNeuralNineKey"
nonce = b"TheNeuralNineNce"
cipher = AES.new(key, AES.MODE_EAX, nonce)

IP = socket.gethostbyname(socket.gethostname())
PORT = 4466
ADDR = (IP, PORT)

SIZE = 1024
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"

def handle_client(conn, addr):
    print(f"[New connection] {addr} connected")
    conn.send("ok@Welcome to the file server".encode(FORMAT))
    
    while True:
        data = conn.recv(SIZE).decode(FORMAT)
        cmd, *cmd_data = data.split("@")



        
        if cmd == "HELP":
            send_data = "ok@"
            send_data += "LIST: List all files from the server\n"
            send_data += "UPLOAD <path>: Upload a file to the server\n"
            send_data += "LOGOUT: Disconnect from the server\n"
            send_data += "HELP: List all commands"
            conn.send(send_data.encode(FORMAT))




        
        elif cmd == "LOGOUT":
            break



        
        elif cmd == "LIST":
            files = os.listdir(SERVER_DATA_PATH)
            send_data = "ok@"
            if not files:
                send_data += "The server directory is empty"
            else:
                send_data += "\n".join(files)
            conn.send(send_data.encode(FORMAT))




        
        elif cmd == "UPLOAD":
            filename = cmd_data[0]
            encrypted_data_b64 = cmd_data[1]
            
            encrypted_data = base64.b64decode(encrypted_data_b64.encode(FORMAT))
            decrypted_data = cipher.decrypt(encrypted_data)
            
            filepath = os.path.join(SERVER_DATA_PATH, filename)
            
            with open(filepath, "wb") as f:
                f.write(decrypted_data)
            
            send_data = "ok@File uploaded"
            conn.send(send_data.encode(FORMAT))


        elif cmd == "DOWNLOAD":
            filename = cmd_data[0]
            filepath = os.path.join(SERVER_DATA_PATH, filename)
            with open(filepath, "rb") as f:
                file_data = f.read()
            encrypted_data = cipher.encrypt(file_data)
            encrypted_data_b64 = base64.b64encode(encrypted_data).decode(FORMAT)  
            send_data = f"{filename}@{encrypted_data_b64}"
            conn.send(send_data.encode(FORMAT))


    
    print(f"[Disconnected] {addr} disconnected")

def main():
    print("[Starting] Server is starting")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()
    print("[Listening] Server is listening on", ADDR)
    
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    main()









