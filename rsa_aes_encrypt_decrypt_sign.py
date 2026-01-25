from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256, TupleHash128
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import os, json

from CH9_HeaderFile import print_msg


def load_user(user_dir):
    if os.path.exists(user_dir):
        with open(user_dir+"/rsa_private.pem", "rb") as f:
            mySK = RSA.import_key(f.read())
        with open(user_dir+"/rsa_public.pem", "rb") as f:
            myPK = RSA.import_key(f.read())
        with open(user_dir+"/rsa_username.pem", "r") as f:
            myName = f.read().strip()
        with open(user_dir+"/rsa_userqueue.pem", "r") as f:
            myQueue = f.read().strip()

        print(f"Loaded existing keys...")
        return myName, myQueue, myPK,mySK
    else :
        print(f"Generating keys...")
        return rsa_key_generator(user_dir)

def hash(myPK, mySK) -> str:
    PublicKeyHash = TupleHash128.new(digest_bytes=8)
    PublicKeyHash.update(myPK)
    myName = PublicKeyHash.hexdigest()
    
    PrivateKeyHash = TupleHash128.new(digest_bytes=32)
    PrivateKeyHash.update(mySK)
    myQueue = PrivateKeyHash.hexdigest()

    return myName, myQueue

def rsa_key_generator(user_dir):
    os.makedirs(user_dir, exist_ok=True)

    RSA_key_pair = RSA.generate(2048)

    mySK = RSA_key_pair.export_key()
    myPK = RSA_key_pair.publickey().export_key()

    myName, myQueue = hash(myPK, mySK)

    with open(user_dir+"/rsa_private.pem", "wb") as f:
        f.write(mySK)

    with open(user_dir+"/rsa_public.pem", "wb") as f:
        f.write(myPK)

    with open(user_dir + "/rsa_username.pem", "w") as f:
        f.write(myName)

    with open(user_dir + "/rsa_userqueue.pem", "w") as f:
        f.write(myQueue)

    return myName, myQueue, RSA_key_pair.publickey(), RSA_key_pair


def encrypt_message(original_message,mySK, PK):
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(PK)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(original_message)

    h = SHA256.new(original_message)
    original_message_signature = pss.new(mySK).sign(h)

    encrypted_msg = {
        "enc_session_key": enc_session_key.hex(),
        "nonce": cipher_aes.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex(),
        "signature": original_message_signature.hex()
    }
    return encrypted_msg

def decrypt_message(encrypted_msg, mySK):
    """Decrypt message without signature verification"""
    enc_session_key = bytes.fromhex(encrypted_msg["enc_session_key"])
    nonce = bytes.fromhex(encrypted_msg["nonce"])
    ciphertext = bytes.fromhex(encrypted_msg["ciphertext"])
    tag = bytes.fromhex(encrypted_msg["tag"])
    
    #mySK = RSA.import_key(open(user_dir+"/rsa_private.pem",'rb').read())

    # Decrypt AES session key with RSA private key
    cipher_rsa = PKCS1_OAEP.new(mySK)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt original message with AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_message, encrypted_msg.get("signature")

def verify_signature(decrypted_message, signature_hex, sender_PK):
    """Verify the signature of a decrypted message"""

    signature = bytes.fromhex(signature_hex)

    
    h = SHA256.new(decrypted_message)
    verifier = pss.new(sender_PK)

    try:
        verifier.verify(h, signature)
        print("[RECEIVER] The SENDER's signature is authentic.")
        return True
    except (ValueError, TypeError):
        print("[RECEIVER] The SENDER's signature is NOT authentic.")
        return False