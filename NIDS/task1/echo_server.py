import socket

IP = '0.0.0.0'
PORT = 9999
BUF_SIZE = 4096

#TODO: make a server-socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
대신
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#TODO: bind the IP, port number to the server-socket
server.bind((IP, PORT))
#TODO: make the socket a listening state
server.listen()


client, addr = server.accept()
print(f"Connected from {addr}")

try:
    while True:
      response = client.recv(BUF_SIZE)
      if not response: break
      #TODO: send the response back to the client
      client.send(response)
      print(response.decode())
except:
    client.close()
    server.close()

