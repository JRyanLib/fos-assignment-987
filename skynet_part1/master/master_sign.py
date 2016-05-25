import os

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

# Generate an RSA public and private key. Set n to 4096bits, e to 65537
generate_key = RSA.generate(bits=4096,e=65537)
# print(generate_key)
public_key = generate_key.publickey().exportKey("PEM")
print(public_key)
private_key = generate_key.exportKey("PEM")
print(private_key)

def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!
    return bytes("Caesar\n", "ascii") + f


if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
