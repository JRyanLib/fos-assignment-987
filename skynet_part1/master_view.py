import os
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

# Protect private key with a passphrase
password = "My Secret!"

def decrypt_valuables(f, fn):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out

    # Retrieve private key from text file for decrypting RSA encryption
    key = open("myprivatekey.txt", "r").read()
    rsa_key = RSA.importKey(key, passphrase=password)
    encr_aes_key = open(os.path.join("pastebot.net", fn + ".AES.key"), "rb").read()
    key_data = rsa_key.decrypt(encr_aes_key)

    # Decrypt AES-CBC encryption by extracting IV and key, then unpad data
    aes_key = key_data[:16]
    iv = key_data[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    paddedData = cipher.decrypt(f) # decrypt the secrets only
    unpaddedData = ANSI_X923_unpad(paddedData, AES.block_size)

    return unpaddedData

# Uses unpad method from tutorial code example
def ANSI_X923_unpad(m, pad_length):
    # The last byte should represent the number of padding bytes added
    required_padding = m[-1]
    # Ensure that there are required_padding - 1 zero bytes
    if m.count(bytes([0]), -required_padding, -1) == required_padding - 1:
        return m[:-required_padding]
    else:
        # Raise an exception in the case of an invalid padding
        raise AssertionError("Padding was invalid")

if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        sys.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    print(decrypt_valuables(f, fn))
