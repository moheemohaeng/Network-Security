import socket

IP = '127.0.0.1'
PORT = 9999
BUF_SIZE = 4096

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#TODO: connect to the server
socket.connect((IP, PORT))
try:
    while True:
        your_input = input().encode()
        #TODO: send your input string to the server
        socket.send(bytes(your_input))
        response = socket.recv(BUF_SIZE)
        if not response: 
            print('client_warning')
            break
        print(response.decode('utf-8'))
except:
    socket.close()

