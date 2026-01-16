from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256, TupleHash128
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import os, json


def load_user(user_dir):
    if os.path.exists(user_dir):
        # with open(user_dir+"/rsa_private.pem", "rb") as f:
        #     private_key = RSA.import_key(f.read())
        with open(user_dir+"/rsa_public.pem", "rb") as f:
            myPK = f.read()
        with open(user_dir+"/rsa_username.pem", "r") as f:
            myName = f.read().strip()
        with open(user_dir+"/rsa_userqueue.pem", "r") as f:
            myQueue = f.read().strip()

        print(f"[USER] Loaded existing keys...")
        return myName, myQueue, myPK
    else :
        print(f"[USER] Generating keys...")
        return generate_user_identity(user_dir)




def generate_user_identity(user_dir):
    os.makedirs(user_dir, exist_ok=True)

    RSA_key_pair = RSA.generate(2048)

    # ... extraction of private key from RSA-KEY pair ...
    mySK = RSA_key_pair.export_key()
    # ... extraction of public key from RSA-KEY pair ...
    myPK = RSA_key_pair.publickey().export_key()
    # ... creation of a HEX-printable username (string) from RSA public key ...

    PublicKeyHash = TupleHash128.new(digest_bytes=8)
    PublicKeyHash.update(myPK)
    myName = PublicKeyHash.hexdigest()
    
    PrivateKeyHash = TupleHash128.new(digest_bytes=32)
    PrivateKeyHash.update(mySK)
    myQueue = PrivateKeyHash.hexdigest()
    
    with open(user_dir+"/rsa_private.pem", "wb") as f:
        f.write(mySK)

    with open(user_dir+"/rsa_public.pem", "wb") as f:
        f.write(myPK)

    with open( user_dir +"/rsa_username.pem", "w") as f:
        f.write(myName)

    with open( user_dir +"/rsa_userqueue.pem", "w") as f:
        f.write(myQueue)

    return myName, myQueue, myPK


def encrypt_message(original_message, user_dir, PK):

    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(PK)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(original_message)

    mySK = RSA.import_key(open(user_dir+"/rsa_private.pem",'rb').read())
    h = SHA256.new(original_message)
    original_message_signature = pss.new(mySK).sign(h)

    package = {
        "enc_session_key": enc_session_key.hex(),
        "nonce": cipher_aes.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex(),
        "signature": original_message_signature.hex()
    }
    return package

def decrypt_message(encrypted_msg, user_dir):
    package = json.loads(encrypted_msg)
    enc_session_key = bytes.fromhex(package["enc_session_key"])
    nonce = bytes.fromhex(package["nonce"])
    ciphertext = bytes.fromhex(package["ciphertext"])
    tag = bytes.fromhex(package["tag"])
    mySK = RSA.import_key(open(user_dir+"/rsa_private.pem",'rb').read())
    rsa_cipher = PKCS1_OAEP.new(mySK)
    session_key = rsa_cipher.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return json.loads(decrypted_message.decode())


def sign_message(message, encrypted_keypair, passphrase):
    keypair = RSA.import_key(encrypted_keypair, passphrase=passphrase)
    private_key = RSA.import_key(keypair.export_key())

    h = SHA256.new(message)
    return pss.new(private_key).sign(h)


def verify_signature(message, signature, sender_public_key):
    pk = RSA.import_key(sender_public_key)
    h = SHA256.new(message)
    try:
        pss.new(pk).verify(h, signature)
        return True
    except ValueError:
        return False
