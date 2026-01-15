from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256, TupleHash128
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP




def generate_user_identity(passphrase='userpass'):

    RSA_key_pair = RSA.generate(2048)

    # ... extraction of private key from RSA-KEY pair ...
    mySK = RSA_key_pair.export_key()
    print(mySK.decode('utf-8'))

    # ... extraction of public key from RSA-KEY pair ...
    myPK = RSA_key_pair.publickey().export_key()
    print(myPK.decode('utf-8'))
    # ... creation of a HEX-printable username (string) from RSA public key ...
    PublicKeyHash = TupleHash128.new(digest_bytes=8)
    PublicKeyHash.update(myPK)
    myName = PublicKeyHash.hexdigest()

    PrivateKeyHash = TupleHash128.new(digest_bytes=32)
    PrivateKeyHash.update(mySK)
    myQueue = PrivateKeyHash.hexdigest()
    with open("./rsa_private.pem", "wb") as f:
        f.write(mySK)
    
    return myName, myQueue, myPK


def encrypt_message(message, receiver_public_key):
    receiver_pk = RSA.import_key(receiver_public_key)

    session_key = get_random_bytes(16)
    enc_session_key = PKCS1_OAEP.new(receiver_pk).encrypt(session_key)

    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    return {
        "esk": enc_session_key,
        "nonce": cipher.nonce,
        "tag": tag,
        "ct": ciphertext
    }


def decrypt_message(enc, encrypted_keypair, passphrase):
    keypair = RSA.import_key(encrypted_keypair, passphrase=passphrase)
    private_key = RSA.import_key(keypair.export_key())

    session_key = PKCS1_OAEP.new(private_key).decrypt(enc["esk"])
    cipher = AES.new(session_key, AES.MODE_EAX, enc["nonce"])
    return cipher.decrypt_and_verify(enc["ct"], enc["tag"])


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
