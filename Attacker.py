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
 
    for i in range(1, n+1):
        x = random.randrange(1, FIELD_SIZE)
        shares.append((x, polynom(x, coefficients)))
 
    return shares
 
def createQBF(dbf_list):
    qbf = BloomFilter(items_count=36, fp_prob=0.00001)
    for filter in dbf_list:
        qbf.bit_array = qbf.bit_array | filter.bit_array
    return qbf


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


#------------Set up listening socket to receive UDP broadcasting from other clients---------------------------
UDPreceivesocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
# Enable reuse of same address/port.
UDPreceivesocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Enable broadcasting mode
UDPreceivesocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# Listening or receiving from the same port for all clients
UDPreceivesocket.bind(("", 37020))
#UDPreceivesocket.setblocking(0)


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

#datareceiver = [UDPreceivesocket, serverTCPsocket, sys.stdin] # For Linux system
datareceiver = [UDPreceivesocket, serverTCPsocket] # For Windows system
import msvcrt # For Windows system to get sys.stdin


def client_receive():
    getcontext().prec = 160 # This parameter is setting the precision of decimal in SSS method.
    threadAlive = True
    dbf_list = []
    T_last_qbf = time.time()
    T_last_dbf = time.time() - 90
    T_EphID_create = time.time() - 15
    T_last_broadcast = time.time() - 3
    dbf = BloomFilter(items_count=36, fp_prob=0.00001)
    i = 0
    j = 0
    bit_true_num = 0
    total_bits = 0
    print("Task 11-A| Broadcast flooding attack")
    print("This results in a significant number of bits set in the nearby nodes, which could lead to a false positive")
    while threadAlive:
        j += 1
        if i == 3:
            i = 0
        if i == 0:
            my_private_key, send_EphID, parameter_num = GenerateKeys()
            #shares = generate_shares(n, t, secret)
            EphID_shares = generate_shares(5, 3, send_EphID)
            T_EphID_create = time.time()
            # Hash client_EphID
            str_EphID = str(send_EphID)
            str_EphID_sha1 = hashlib.sha1(str_EphID.encode()).digest() # a binary
        msg = (str_EphID_sha1, EphID_shares[i]) # shares[i] = (x, y)
        i += 1
        broadcast_msg = pickle.dumps(msg)
        # Broadcast msg
        broadcastsocket.sendto(broadcast_msg, ('<broadcast>', 37020))
        T_last_broadcast = time.time()
        if time.time() - T_last_dbf >= 90: # A new DBF is generated every 90 seconds.
            str_dbf = str(dbf.bit_array)
            for c in str_dbf:
                if c == '1':
                    bit_true_num += 1
                total_bits += 1
            dbf_list.append(dbf)
            dbf = BloomFilter(items_count=36, fp_prob=0.00001)
            T_last_dbf = time.time()
        
        if time.time() - T_last_qbf > 540: # QBF combines all DBF and submits to server
            qbf = createQBF(dbf_list)
            dbf_list = []
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
                    qbf = createQBF(dbf_list)
                    qbf.bit_array.setall(1)
                    msgToServer = pickle.dumps(("positive", qbf))
                    serverTCPsocket.sendall(msgToServer)
                    sys.exit()
                elif sysInput == 'q':
                    sys.exit()
            elif datasource == serverTCPsocket:
                # Add code when datasource = serverTCPsocket
                msgFromServer = datasource.recv(1024).decode('utf-8')
             
#--------------------This part is handling the UDP client EncID-----------------
        if addr_client[1] != broadcastsocket.getsockname()[1] and data_client != (0,0): # ingore the broadcast message from myself.
            if data_client[0] not in dict_received_EphID:
                # If the received hash (EnpID/other client's public key) is a new one, this means a new client starts broadcasting, then add the new socket, EphID and time of creating
                T_value_create = time.time()
                dict_received_EphID[data_client[0]] = [[data_client[1]], time.time()]
            elif data_client[0] in dict_received_EphID and data_client[1] not in dict_received_EphID[data_client[0]][0]:
                # If the received hash (EnpID/other client's public key) is a new one, append the share to the share list of the existing key
                dict_received_EphID[data_client[0]][0].append(data_client[1]) # add the shares to the shared list
            if len(dict_received_EphID[data_client[0]][0]) == 3:
                # if there are three shares in the same share list, then calculate the share value using SSS
                shares_list = dict_received_EphID[data_client[0]][0]
                reconst_secret = reconstruct_secret(shares_list) # reconstrt_secret is int
                str_reconst_secret = str(reconst_secret)
                str_reconst_secret_sha1 = hashlib.sha1(str_reconst_secret.encode()).digest()
                # Compare the received hashed(EnpID) with my hash calculation of the reconstructed secret.
                if str_reconst_secret_sha1 == data_client[0]: # reconstructed secret = hashed secret
                    # If reconstructed secret == hashed secret, then new EphID is received.
                    received_EphID = reconst_secret
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
                        list_EncID.append(EncID)
                        dbf.add(EncID.to_bytes((EncID.bit_length() + 7) // 8, 'little'))
                    del dict_received_EphID[data_client[0]]

#------------------Main thread starting-------------------------------
receive_thread = threading.Thread(target=client_receive)
receive_thread.start()
