import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out

    key = open("myprivatekey.txt", "r").read()
    decryption_key = RSA.importKey(key, passphrase=password)
    priv_key = PKCS1_v1_5.new(decryption_key)
    decrypt_msg = decryption_key.decrypt(f)
    print(decrypt_msg)

    # decoded_text = str(f, 'ascii')
    # print(decoded_text)


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
