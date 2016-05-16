import struct

from Crypto.Random import random
from Crypto.Cipher import AES # change from XOR to AES ******
from Crypto.Util import Counter #importing counter for CTR mode
from Crypto.Hash import HMAC, SHA256

from dh import create_dh_key, calculate_dh_secret
#from hmac import create_hash, check_hash

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
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
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

        # Create a counter from PyCrypto library. Has 128 bits and uses a
        # randomly generated initial value
        counter = Crypto.Util.Counter.new(128, random.randint(10000,100000))
        # Creating AES cipher with 16 bit key, counter mode and counter initialised
        # in previous line
        self.cipher = AES.new(shared_hash[:16], AES.MODE_CTR, counter = counter)

    def send(self, data):
        if self.cipher:
            #bytes_data = bytes(data, "ascii")
            hashed_data = HMAC.new(str(random.getrandbits(256)), data, SHA256.new())
            #print (hashed_data.hexdigest())
            #byte_hashed = bytes(str(hashed_data.hexdigest()), 'ascii')
            encrypted_data = self.cipher.encrypt(data) #+ hashed_data.hexdigest())
            if self.verbose:
                print("Original data: {}".format(data))
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
        if self.cipher:
            data = self.cipher.decrypt(encrypted_data)#[:pkt_len-32])
            #hashed_data = self.cipher.decrypt(encrypted_data[pkt_len-32:])
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
