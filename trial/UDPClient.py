from socket import *
serverName = gethostname() # the loopback address, refers to the IP address of the machine you are running the client on.
serverPort = 7001
clientSocket = socket(AF_INET, SOCK_DGRAM)
message = input('Input a string:')
clientSocket.sendto(message.encode(),(serverName, serverPort))
modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
print(f'From the server {serverName}: ', modifiedMessage.decode())
clientSocket.close()
