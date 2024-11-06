import socket
serverPort = 7001
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSocket.bind(('', serverPort))
print(f'The server is listening on {serverPort}')
while True:
    packet, clientAddress = serverSocket.recvfrom(65535)
    modifiedMessage = packet.decode().upper()
    print(f'From the client {clientAddress}: ', modifiedMessage)
    serverSocket.sendto(modifiedMessage.encode(), clientAddress)
