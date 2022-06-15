#---------------------Diffie Hellman Exchange---------------------------------
#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from bloomfilter import BloomFilter

import time

###########
# METHODS #
###########

def GenerateKeys():
    p = 11682611595708060452747037040162464231184906230176674797309781227748392035720002318622326190262213186021989629908104715567416803567020238784100659652627107
    g = 2
    q = None

    parameter_num = dh.DHParameterNumbers(p, g, q)
    parameters = parameter_num.parameters()

    client_private_key = parameters.generate_private_key()
    client_public_key = client_private_key.public_key()
    client_pub_numy = client_public_key.public_numbers().y
    client_EphID = client_pub_numy
    # print("----------------------------------------------")
    # print("Task 1  | (15s) Generated keys:")
    # print(str(client_private_key)[:5]+"... , "+str(client_EphID)[:5]+"...")

    return client_private_key, client_EphID, parameter_num

#------------------Start of SSS------------------------------------
#-----https://www.geeksforgeeks.org/implementing-shamirs-secret-sharing-scheme-in-python/
import random
from math import ceil
import math
from decimal import *
getcontext().prec = 160

FIELD_SIZE = 10**50

def reconstruct_secret(shares):
    """
    Combines individual shares (points on graph)
    using Lagranges interpolation.
 
    `shares` is a list of points (x, y) belonging to a
    polynomial with a constant of our key.
    """
    sums = 0
    prod_arr = []
 
    for j, share_j in enumerate(shares):
        xj, yj = share_j
        prod = Decimal(1)
 
        for i, share_i in enumerate(shares):
            xi, _ = share_i
            if i != j:
                prod *= Decimal(Decimal(xi)/(xi-xj))
        prod *= Decimal(yj)
        sums += Decimal(prod)
    return round(sums)

def polynom(x, coefficients):
    """
    This generates a single point on the graph of given polynomial
    in `x`. The polynomial is given by the list of `coefficients`.
    """
    point = 0
    # Loop through reversed list, so that indices from enumerate match the
    # actual coefficient indices
    for coefficient_index, coefficient_value in enumerate(coefficients[::-1]):
        point += x ** coefficient_index * coefficient_value
    return point

def coeff(t, secret):
    """
    Randomly generate a list of coefficients for a polynomial with
    degree of `t` - 1, whose constant is `secret`.
 
    For example with a 3rd degree coefficient like this:
        3x^3 + 4x^2 + 18x + 554
 
        554 is the secret, and the polynomial degree + 1 is
        how many points are needed to recover this secret.
        (in this case it's 4 points).
    """
    coeff = [random.randrange(0, FIELD_SIZE) for _ in range(t - 1)]
    coeff.append(secret)
    return coeff

def generate_shares(n, m, secret):
    """
    Split given `secret` into `n` shares with minimum threshold
    of `m` shares to recover this `secret`, using SSS algorithm.
    """
    coefficients = coeff(m, secret)
    shares = []

    # print("Task 2  | (15s) Generating 5 shares:")
    for i in range(1, n+1):
        x = random.randrange(1, FIELD_SIZE)
        shares.append((x, polynom(x, coefficients)))
        # print(str(shares[i-1])[1:6]+"... ",end="")
    # print("")

    return shares

def createQBF(dbf_list, positive):
    qbf = BloomFilter(items_count=36, fp_prob=0.00001)
    for filter in dbf_list:
        qbf.bit_array = qbf.bit_array | filter.bit_array
    if positive:
        # print("Task 9  | Combined DBFs into CBF:")
        # print(getSetBits(qbf.bit_array))
        # print("Task 9  | Sending CBF to server")
        pass
    else:
        # print("Task 8  | Combined DBFs into QBF:")
        # print(getSetBits(qbf.bit_array))
        # print("Task 10-A| Sending QBF to server")
        pass
    return qbf

def getSetBits(bit_array):
    setBits = []
    for index, bit in enumerate(str(bit_array)):
        if bit == '1':
            setBits.append(index)
    return setBits

def printNumSetBits(bit_array):
    num_bits_set = 0
    total_bits = 0
    for c in str(bit_array):
        if c == '1':
            num_bits_set += 1
        total_bits += 1
    print("Task 11-A| True bits: "+str(num_bits_set)+"/"+str(total_bits))

########
# MAIN #
########

#-------------------------Setup UDP broadcasting between clients-------------------------
import socket
import threading, select
import sys, time

#-------------Set up broadcast socket-------------------------------
broadcastsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
# Enable reuse of same address/port.
# Details refer to https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ for more information
# Enable broadcasting mode
broadcastsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
broadcastsocket.setblocking(0)

#------------Set up listening socket to receive UDP broadcasting from other clients---------------------------
UDPreceivesocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
# Enable reuse of same address/port.
UDPreceivesocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Enable broadcasting mode
UDPreceivesocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# Listening or receiving from the same port for all clients
UDPreceivesocket.bind(("", 37020))
UDPreceivesocket.setblocking(0)

#-----------------Set up a dictionary to record the received number of same EphID--------------------
dict_received_EphID = {}
list_EncID = []

#-------------Set up TCP connection between client and server-------------------------
serverHost = "127.0.0.1"
serverPort = 55000
serverAddress = (serverHost, serverPort)
serverTCPsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # The socket between client and server
serverTCPsocket.connect(serverAddress)     # The connection between client and server
# For laddr use mySocket.getsockname() and for raddr use mySocket.getpeername()
laddr = serverTCPsocket.getsockname() 

import hashlib
import pickle # pickle allows to send a list using UDP or TCP which integrated encode/decode a list
import random

datareceiver = [UDPreceivesocket, serverTCPsocket] # For Windows system
import msvcrt # For Windows system to get sys.stdin

def client_receive():
    getcontext().prec = 160 # This parameter is setting the precision of decimal in SSS method.
    threadAlive = True
    dbf_list = []
    dbf_count = 0
    T_last_qbf = time.time()
    T_last_dbf = time.time() - 90
    T_EphID_create = time.time() - 15
    T_last_broadcast = time.time() - 3
    dbf = BloomFilter(items_count=36, fp_prob=0.00001)
    i = 0
    j = 0
    while threadAlive:
        if time.time() - T_EphID_create >= 15: # A new EphID is generated every 15 seconds.
            j += 1
            my_private_key, send_EphID, parameter_num = GenerateKeys()            
            EphID_shares = generate_shares(5, 3, send_EphID)
            T_EphID_create = time.time()

            # Hash client_EphID
            str_EphID = str(send_EphID)
            str_EphID_sha1 = hashlib.sha1(str_EphID.encode()).digest() # a binary

            i = 0 # i to count the share index

        if time.time() - T_last_broadcast >= 3: # every 3 second, broadcast a EphID_shares
            x = random.random()
            if x >= 0.5: # only when random >= 0.5 transfer the shares[i]
                msg = (str_EphID_sha1, EphID_shares[i]) # shares[i] = (x, y)
                i += 1
                broadcast_msg = pickle.dumps(msg)
                # Broadcast msg
                broadcastsocket.sendto(broadcast_msg, ('<broadcast>', 37020))
                T_last_broadcast = time.time()
                # print("Task 3-A| (3s) Sending share "+str(i))
            else: # if random < 0.5, when skip share[i]
                # print("Task 3-A| (3s) Share "+str(i)+" dropped")
                i += 1 # This index shift must be kept here when random<0.5. It skips the share_i and index shifts to the next index share_i+1
                msg0 = (0, 0) # This msg0 broadcast can be deleted with select.select()
                broadcast_msg = pickle.dumps(msg0)
                broadcastsocket.sendto(broadcast_msg, ('<broadcast>', 37020))
                T_last_broadcast = time.time()

        if time.time() - T_last_dbf >= 90: # A new DBF is generated every 90 seconds.
            dbf_count += 1
            dbf_list.append(dbf)
            printNumSetBits(dbf.bit_array)
            dbf = BloomFilter(items_count=36, fp_prob=0.00001)
            print("---------------------------------------------")
            if (dbf_count > 6):
                print("Task 7-B| A new DBF 1 has been created")
                dbf_count = 1
            else:
                print("Task 7-B| A new DBF "+str(dbf_count)+" has been created")
            T_last_dbf = time.time()
        
        if time.time() - T_last_qbf > 540: # QBF combines all DBF and submits to server
            print("##############################################")
            print("                9min elapsed")
            print("##############################################")
            qbf = createQBF(dbf_list, False)
            printNumSetBits(qbf.bit_array)
            dbf_list = []
            dbf_count = 0
            dbf = BloomFilter(items_count=36, fp_prob=0.00001)
            T_last_qbf = time.time()
            msgToServer = pickle.dumps(("negative", qbf))
            serverTCPsocket.sendall(msgToServer)

        # select.select unblocking I/O
        timeout_in_seconds = 0.1
        readyinput, readyoutput, readyexception = select.select(datareceiver, [], [], timeout_in_seconds)
        if msvcrt.kbhit(): readyinput.append(sys.stdin) # For Windows system to get sys.stdin
        for datasource in readyinput:
        # receive msg from other clients
            if datasource == UDPreceivesocket:
                data_client, addr_client = datasource.recvfrom(1024)
                data_client = pickle.loads(data_client) # to decode a list msg = [str_EphID_sha1, EphID_shares[i]] # shares[i] = (x, y)
            elif datasource == sys.stdin:
                sysInput = input()
                if sysInput.lower() == 'positive':
                    dbf_list.append(dbf)
                    qbf = createQBF(dbf_list, True)
                    msgToServer = pickle.dumps(("positive", qbf))
                    serverTCPsocket.sendall(msgToServer)
                    sys.exit()
                elif sysInput == 'q':
                    sys.exit()
            elif datasource == serverTCPsocket:
                # Add code when datasource = serverTCPsocket
                msgFromServer = datasource.recv(1024).decode('utf-8')
                print(msgFromServer)
             
        #--------------------This part is handling the UDP client EncID-----------------
        if addr_client[1] != broadcastsocket.getsockname()[1] and data_client != (0,0): # ingore the broadcast message from myself.
            if data_client[0] not in dict_received_EphID:
                # If the received hash (EnpID/other client's public key) is a new one, this means a new client starts broadcasting, then add the new socket, EphID and time of creating
                T_value_create = time.time()
                # print("Task 3-B| (3s) Received share: "+str(data_client[1])[1:6]+"...")
                dict_received_EphID[data_client[0]] = [[data_client[1]], time.time()]
                # print("Task 3-C| (3s) Collected "+str(len(dict_received_EphID[data_client[0]][0]))+" shares")
            elif data_client[0] in dict_received_EphID and data_client[1] not in dict_received_EphID[data_client[0]][0]:
                # If the received hash (EnpID/other client's public key) is a new one, append the share to the share list of the existing key
                # print("Task 3-B| (3s) Received share: "+str(data_client[1])[1:6]+"...")
                dict_received_EphID[data_client[0]][0].append(data_client[1]) # add the shares to the shared list
                # print("Task 3-C| (3s) Collected "+str(len(dict_received_EphID[data_client[0]][0]))+" shares")
            if len(dict_received_EphID[data_client[0]][0]) == 3:
                # if there are three shares in the same share list, then calculate the share value using SSS
                shares_list = dict_received_EphID[data_client[0]][0]
                reconst_secret = reconstruct_secret(shares_list) # reconstrt_secret is int
                str_reconst_secret = str(reconst_secret)
                str_reconst_secret_sha1 = hashlib.sha1(str_reconst_secret.encode()).digest()
                # Compare the received hashed(EnpID) with my hash calculation of the reconstructed secret.
                # print("Task 4-B| Verifying hash: "+str(str_reconst_secret_sha1)[:7]+" vs "+str(data_client[0])[:7])
                if str_reconst_secret_sha1 == data_client[0]: # reconstructed secret = hashed secret
                    # print("Task 4-B| Hash matched.")
                    # If reconstructed secret == hashed secret, then new EphID is received.
                    received_EphID = reconst_secret
                    # print("Task 4-A| Reconstructed EphID: "+str(received_EphID)[:5])
                    # Using the DH method to calculated the share_secret
                    # First calcualte the publicNumbers, which are the DH curve parameter
                    received_public_num = dh.DHPublicNumbers(received_EphID, parameter_num)
                    # Second calculate the public key of the other client using the received EnpID.
                    # Public key is an object in the Library which includes the point value of y, curve parameters and so on.
                    received_public_key = received_public_num.public_key()
                    # Finally, using my private key and the public_key object to calculate the shared_key
                    client_shared_key = my_private_key.exchange(received_public_key)
                    # The share_key is a byte type. Transfer it into integer using byteorder 'big'. This (byteorder 'big') is specified in the Library page.
                    EncID = int.from_bytes(client_shared_key, byteorder='big')
                    # If the EncID is not in the list_EncID, append it to the list_EncID
                    if EncID not in list_EncID:
                        # print("---------------------------------")
                        # print("Task 5-A/B| Computed EncID: "+str(EncID)[:5])
                        # print("---------------------------------")
                        list_EncID.append(EncID)
                        dbf.add(EncID.to_bytes((EncID.bit_length() + 7) // 8, 'little'))
                        # print("Task 6  | Encode EncID into DBF, delete EncID")
                        # print("Task 7-A| State of DBF "+str(dbf_count)+":")
                        # print(getSetBits(dbf.bit_array))
                        #print("updating dbf")
                        # print(str(dbf.bit_array))
                        # print("==============================================================================================")
                        #print('EncID = ', EncID)
                        #print("=================================")
                        # add the EncID ( the reconstructed EnpID) to the BF
                    # After the EncID is generated, delete this item from the dictionary.
                    del dict_received_EphID[data_client[0]]

#------------------Main thread starting-------------------------------
receive_thread = threading.Thread(target=client_receive)
receive_thread.start()
