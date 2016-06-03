import os

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import random


# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []

###

def save_valuable(data):
    valuables.append(data)

def encrypt_for_master(data):
    # Encrypt the file so it can only be read by the bot master

    # Generate key and IV for AES encryption with 256bits key size
    aes_encryption_key = random.getrandbits(128) # export key and name aes encryption
    iv = random.getrandbits(AES.block_size)
    cipher = AES.new(aes_encryption_key, AES.MODE_CFB, iv)
    encrypted_data = cipher.encrypt(data)
    print(aes_encryption_key)  # Test print. TO BE REMOVE
    print(encrypted_data)  # Test print. TO BE REMOVE

    # Obtain public key from text file for encrypting aes_msg
    pub_key = open("mypublickey.txt", "r").read()
    rsa_encryption_key = RSA.importKey(pub_key)
    encrypt_msg = rsa_encryption_key.encrypt(aes_encryption_key) ## Encrpyt aes encryption key
    print(encrypt_msg)  # encrpyted key
    return data

# encrypt_for_master(b"Attack at dawn") # Test print. TO BE REMOVE

def upload_valuables_to_pastebot(fn):
    # Encrypt the valuables so only the bot master can read them
    valuable_data = "\n".join(valuables)
    valuable_data = bytes(valuable_data, "ascii")
    encrypted_master = encrypt_for_master(valuable_data)

    # "Upload" it to pastebot (i.e. save in pastebot folder)
    f = open(os.path.join("pastebot.net", fn), "wb")
    f.write(encrypted_master)
    f.close()

    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

###

def verify_file(f):
    # Verify the file was sent by the bot master
    # TODO: For Part 2, you'll use public key crypto here

    file_key = open("mypublickey.txt", "r").read()
    key = RSA.importKey (file_key)
    fn = open(os.path.join("pastebot.net","hello.fbi"), "rb").read()
    hashed_file = SHA256.new(fn) #need to put original file here
    signer = PKCS1_v1_5.new(key)
    if signer.verify(hashed_file, f):
        return True
    else:
        return False

def process_file(fn, f):
    if verify_file(f):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    process_file(fn, f)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)

###

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(fn)
    sconn.send(filestore[fn])

def run_file(f):
    # If the file can be run,
    # run the commands
    pass
