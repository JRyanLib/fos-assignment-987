from Crypto.Hash import SHA256, HMAC

def create_hash(key, data):
    hashed_msg = HMAC.new(key, data, SHA256.new())
    return hashed_msg

def check_hash(key, data, given_hash):
    hashed_msg = HMAC.new(key, data, SHA256.new())
    if given_hash == hashed_msg.hexdigest():
        print ("This message is not altered")
        return
    else:
        print ("This message is altered")
        return
    

