import argparse
import binascii
import socket
import sys
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA

# HOST = 127.0.0.1
PORT = 9998
pwd = b'securepassword'

def genkey():
    mykey = RSA.generate(4096, randfunc=get_random_bytes, e=65537)

    # Private RSA key
    with open("myprivkey.pem", "wb") as f:
        data = mykey.export_key(format='PEM', passphrase=pwd, pkcs=1.5, protection=None, randfunc=None, prot_params=None)
        f.write(data)
    
    # Public RSA key
    with open("mypubkey.pem", "wb") as f:
        data = mykey.public_key().export_key(format='PEM', passphrase=None, pkcs=1.5, protection=None, randfunc=None, prot_params=None)
        f.write(data)
    
    # # Print final signed message example.
    # test = signMessage('test')
    # print(test)
    # print('decoded:\n')
    # print(test.decode())
        
    # # Check that I can read key correctly.
    # with open("myprivkey.pem", "rb") as f:
    #     data = f.read()
    #     mykey2 = RSA.import_key(data, pwd)
    # print(mykey==mykey2)
pass

def start_client(hostname):
    # Create an IPv4 TCP socket for the client
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect socket to an existing hostname on port PORT, else fail and stop program.
    try:
        client_socket.connect((hostname, PORT))
    except ValueError:
        client_socket.close()
        sys.exit(0)
    return client_socket

def padNumber(number):
    return '0' * (4-len(str(number))) + str(number)

def signMessage(message):
    mLength = padNumber(len(message))
                            
    with open("myprivkey.pem", "rb") as f:
        data = f.read()
        mykey = RSA.import_key(data, pwd)

    h = SHA256.new(message.encode('utf-8'))
    signature = pkcs1_15.new(mykey).sign(h)

    signature_hex = binascii.hexlify(signature)
    sigLength = padNumber(len(signature_hex))
    
    signedMessage = bytes(mLength + message + sigLength,'utf-8') + signature_hex
    
    return signedMessage

def main():
    # Create argument parser to handle command line options
    parser = argparse.ArgumentParser(description='Generate key or connect to server.')
    # Set it so that only one of server or client options can be selected
    group = parser.add_mutually_exclusive_group(required=True)
    # If server, set arg.s to True
    group.add_argument('--genkey', action='store_true', help='Generate a RSA key pair')
    # If client, set arg.c to the provided hostname argument
    group.add_argument('--c', metavar='hostname', type=str, help='Start as client and connect to hostname')
    # Add arguments for the confidentiality and authenticity keys
    parser.add_argument('--m', metavar='message', type=str, help='Message', required=False)
    # Parse inputs from the command line when the script was called
    args = parser.parse_args()

    # Check if both --c and --m arguments are provided or if only --genkey argument is provided
    if not (args.genkey or (args.c and args.m)):
        parser.error('Either --genkey should be called alone, or both --c and --m should be called.')


    if args.genkey:
        # Start the server
        genkey()
    
    else:
        # Start the client and connect to the hostname provided as an argument
        sock = start_client(args.c)
    
        # Read message from call
        message = args.m
        
        # Get encoding of "len(m), m, len(sig), sig".
        signedMessage = signMessage(message)

        sock.sendall(signedMessage)
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        sys.exit(0)
        
if __name__ == "__main__":
    main()