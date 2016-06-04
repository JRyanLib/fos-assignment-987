import os, sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES


# Protect private key with a passphrase
password = "My Secret!"

def decrypt_valuables(f, fn):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out

    print("File: {}".format(f))

    key = open("myprivatekey.txt", "r").read()
    rsa_key = RSA.importKey(key, passphrase=password)
    encr_aes_key = open(os.path.join("pastebot.net", fn + ".AES.key"), "rb").read()
    aes_key = rsa_key.decrypt(encr_aes_key)

    # Extracts iv from data:f
    # iv = f[:16]
    # print(iv)
    # cipher = AES.new(f[:16], AES.MODE_CBC, iv)
    # paddedData = cipher.decrypt(f[16:])
    # unpaddedData = ANSI_X923_unpad(paddedData, AES.block_size)
    # print(unpaddedData)
    # return unpaddedData
    print("test")

    # # decoded_text = str(f, 'ascii')
    # # print(decoded_text)

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
    decrypt_valuables(f, fn)
