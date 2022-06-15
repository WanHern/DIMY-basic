# Server code

# Server will receive QBF from each client, and compare each QBF with the CQF (positive case).
# The comparison will check for each digit of QBF with the corresponding digit of CQF. If both are 1, then count += 1.
# Finally, if count > 3 the number of hashed functions in Bloom Filter, than it is a close contact with high possibility.
"""
reference: The device combines their DBF covering the last 21 days into a single CBF of size 100KB (equal in size to the
DBF). The set union function is utilised as the combination process for the DBFs to construct a CBF. For example, all
‘1’-bit existing information in the DBFs are accumulated into one CBF by performing a bit-wise OR merging.
"""

import socket
import threading
from threading import Thread
import sys, select
import time
import pickle

#-------------Set up TCP connection between client and server-------------------------
serverHost = "127.0.0.1"
serverPort = 55000
serverAddress = (serverHost, serverPort)

# define socket for the server side and bind address
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(serverAddress)
serversocket.listen(10)

dictsocketaddress = {}  # key is clientsocket. Value is the address/port of each client.

listPositiveCBF = [] # contains all the positive CBF from the postive clients. There may be more than one positive clients.

# define thread
class ClientThread(Thread):
    def __init__(self, clientsocket):
        Thread.__init__(self)
        self.clientsocket = clientsocket
        self.clientAlive = False    # To record the status of each ClientThread, True will keep self.clientsocket.recv(1024), False will stop receive message.
        self.QBF = 0  # To store QBF from negative client.
        self.positive = False
        
        print("===== New connection created for: ", dictsocketaddress[clientsocket])
        self.clientAlive = True

    def run(self):
        recvmessage = 'Server started'
        x = 0   # To record how many times of recvmessage == '', which can detect the Ctrl + c force shut down at the user end.
        datareceiver = [self.clientsocket]
        while self.clientAlive:
            readyinput, readyoutput, readyexception = select.select(datareceiver, [], [])
            for datasource in readyinput:
                if datasource == self.clientsocket:
                    try:
                        recvmessage = pickle.loads(self.clientsocket.recv(128*1024*8*2))
                    except:
                        self.clientAlive = False
                        break                    
                    if recvmessage[0] == 'negative':
                        print("Task 10-A| QBF received")
                        sendmessage = 'server confirming received message from ' + serversocket.getsockname()[0] + ' ' + str(serversocket.getsockname()[1])
                        self.clientsocket.send(sendmessage.encode())
                        # Check against positive CBF
                        print("Task 10-C| Matching QBF with CBF...")
                        for cbf in listPositiveCBF:
                            intersection = recvmessage[1].bit_array & cbf.bit_array
                            similarity = 0
                            for c in str(intersection):
                                if c == '1':
                                    similarity += 1
                            print("Similarity: "+str(similarity)+"/3")
                            if similarity >= 3:
                                print("Result: Matched")
                                self.clientsocket.send('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\nTask 10-B| Risk analysis: MATCHED, you are at risk\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'.encode())
                            else:
                                print("Result: Not matched")
                                self.clientsocket.send('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\nTask 10-B| Risk analysis: NOT MATCHED, you are not at risk\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'.encode())
                    elif recvmessage[0] == 'positive':
                        print("Task 9   | CBF received")
                        listPositiveCBF.append(recvmessage[1])
                    if not recvmessage:
                        break

#--- Main ---     
def receive():
    while True:
        clientsocket, address = serversocket.accept()
        dictsocketaddress[clientsocket] = address
        clientsocket.send("you are now connected to server ('127.0.0.1', 55000)".encode('utf-8'))
        clientThread = ClientThread(clientsocket)
        clientThread.start()

if __name__ == '__main__':
    receive()
