import struct

from Crypto.Random import random
from Crypto.Cipher import AES # change from XOR to AES ******
from Crypto.Util import Counter #importing counter for CTR mode
from Crypto.Hash import HMAC, SHA256

from lib.helpers import read_hex
from dh import create_dh_key, calculate_dh_secret


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.key = None
        self.from_bot1_seed = None
        self.from_bot2_seed = None
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.key = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.key))

        # Create a counter from PyCrypto library. Has 128 bits and uses a randomly generated initial value
        counter = Counter.new(128)

        # Creating AES cipher with 16 bit key, counter mode and counter initialised in previous line
        self.cipher = AES.new(self.key[:16], AES.MODE_CTR, counter=counter) # Changes from XOR to AES

        self.send_seed = read_hex(self.key[:4])
        self.recv_seed = self.send_seed
        print("Send seed: {}".format(self.send_seed))
        print("Recv seed: {}".format(self.recv_seed))

    def lcg_generate(self, seed):
        print("Starting the LCG with seed =", seed)
        # Set up lcg for the counters to prevent replay attacks
        a, b = 15, 31
        c = 2 ** 8 - 1

        return (a * seed + b) % c

    def send(self, data):
        if self.cipher:
            self.send_seed = self.lcg_generate(self.send_seed)
            bytes_seed = bytes(str(self.send_seed%10), "ascii")
            hashed_data = HMAC.new(bytes(self.key[:32], 'ascii'), data, SHA256.new())
            encrypted_data = self.cipher.encrypt(data + hashed_data.digest() + bytes_seed)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Hash: {}".format(hashed_data.hexdigest()))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        msg_length = int(len(encrypted_data))
        if self.cipher:
            self.recv_seed = self.lcg_generate(self.recv_seed)
            comb_data = self.cipher.decrypt(encrypted_data)
            data = comb_data[:msg_length-33]
            given_hashed_data = comb_data[msg_length-33:msg_length-1]
            given_seed = comb_data[msg_length-1:]
            hashed_data = HMAC.new(bytes(self.key[:32], 'ascii'), data, SHA256)
            seed_is_same = False
            
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
                print("Calculated Hash: {}".format(hashed_data.hexdigest()))

            current_seed = bytes(str(self.recv_seed % 10), 'ascii')
            
            if given_seed == current_seed:
                seed_is_same = True

            if given_hashed_data == hashed_data.digest() and seed_is_same:
                print('Message can be trusted')
            else:
                print('Warning! Message is altered!!')
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
