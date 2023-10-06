import socket
import sys

def port_scanner(target_ip, start_portno, end_portno):

    for port_number in range(start_portno, end_portno):
        #TODO: your code here
        try:
            ip = target_ip
            scanner_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            scanner_socket.connect((ip, port_number))
            #TODO: your code here
            scanner_socket.send(b'testing\n')
            result = scanner_socket.recv(4096)
            print('%d TCP OPEN'% port_number)



        except ConnectionRefusedError:
            continue
        except TimeoutError:
            continue
        except:
            pass


if __name__ == '__main__':
        
    target_ip = sys.argv[1]
    start_portno = int(sys.argv[2])
    end_portno = int(sys.argv[3])

    port_scanner(target_ip, start_portno, end_portno)

