import os

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

# Protect private key with a passphrase
password = "My Secret!"

def generate_keys():
    # Generate an 4096 RSA public and private key.
    generate_key = RSA.generate(bits=4096, e=65537)

    # Get the public key and export it
    public_key = generate_key.publickey().exportKey()
    print("Public Key: {}".format(public_key))

    # Get the private key, store with passphrase and export it
    password_private_key = generate_key.exportKey(passphrase = password)

    # Store the export private key into der file type
    key_file = open("myprivatekey.der", "wb")
    key_file.write(password_private_key)
    key_file.close()
    print("Private Key: {}".format(password_private_key))

# Testing for generate_keys
generate_keys()

def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out
    decoded_text = str(f, 'ascii')
    print(decoded_text)


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
