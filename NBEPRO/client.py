import os
import socket
import base64
from Crypto.Cipher import AES

# Define AES encryption parameters
key = b"TheNeuralNineKey"
nonce = b"TheNeuralNineNce"
cipher = AES.new(key, AES.MODE_EAX, nonce)

# Server address and port
IP = socket.gethostbyname(socket.gethostname())
PORT = 4466
ADDR = (IP, PORT)

SIZE = 1024
FORMAT = "utf-8"

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)
    
    while True:
        data = client.recv(SIZE).decode(FORMAT)
        cmd, msg = data.split("@")
        
        if cmd == "ok":
            print(f"{msg}")
        elif cmd == "DISCONNECTED":
            print(f"{msg}")
            break
        else:
            filepath = os.path.join("client_data", filename)
            encrypted_data = base64.b64decode(msg.encode(FORMAT))
            decrypted_data = cipher.decrypt(encrypted_data)
            with open(filepath, "wb") as f:
                f.write(decrypted_data)
        
        user_input = input("> ")
        user_data = user_input.split(" ")
        cmd = user_data[0]
        
        if cmd == "HELP":
            client.send(cmd.encode(FORMAT))
        
        elif cmd == "LOGOUT":
            client.send(cmd.encode(FORMAT))
            break
        
        elif cmd == "LIST":
            client.send(cmd.encode(FORMAT))
        
        elif cmd == "UPLOAD":
            path = user_data[1]
            filename = os.path.basename(path)
            
            with open(path, "rb") as f:
                file_data = f.read()
            
            encrypted_data = cipher.encrypt(file_data)
            encrypted_data_b64 = base64.b64encode(encrypted_data).decode(FORMAT)
            
            send_data = f"{cmd}@{filename}@{encrypted_data_b64}"
            client.send(send_data.encode(FORMAT))


        elif cmd == "DOWNLOAD":
            filename = user_data[1]
            send_data = f"{cmd}@{filename}"
            client.send(send_data.encode(FORMAT))
    print("Disconnected from the server")
    client.close()

if __name__ == "__main__":
    main()




