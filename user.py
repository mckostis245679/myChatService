import json, threading
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from crypto_layer import *
import pika

#rabbitmq set up
connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))
channel = connection.channel()

BROKER_QUEUE = "broker_public"
passphrase = "userpass"

# ---------------- IDENTITY ----------------
myName, myQueue, myPK = generate_user_identity(passphrase)
print(f"[USER] username = {myName}")

#create a unique queue for the user
channel.queue_declare(queue=myQueue, durable=True)

msgBrokerPK = RSA.import_key(open("broker_public.pem").read())
cipher_rsa = PKCS1_OAEP.new(msgBrokerPK)

# ---------------- REGISTER ----------------
def register():
    original_message = {
        "type": "register",
        "userName": myName,
        "userPublicKey": myPK.decode('utf-8'),
        "userQueue": myQueue
    }
    original_message = json.dumps(original_message).encode()

    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(msgBrokerPK)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(original_message)
    mySK = RSA.import_key(open("./rsa_private.pem",'rb').read())
    h = SHA256.new(original_message)
    original_message_signature = pss.new(mySK).sign(h)

    package = {
        "enc_session_key": enc_session_key.hex(),
        "nonce": cipher_aes.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex(),
        "signature": original_message_signature.hex()
    }

    #send message to rabbitmq broker
    channel.basic_publish(exchange="", routing_key=BROKER_QUEUE,
                     body=json.dumps(package).encode())
    print("[USER] Registered")

# # ---------------- SEND MESSAGE ----------------
# def send_message():
#     receiver = input("Receiver username: ")
#     text = input("Message: ").encode()

#     enc = encrypt_message(text, receiver_public_key)
#     sig = sign_message(text, enc_keypair, passphrase)

#     msg = {
#         "type": "send",
#         "sender": username,
#         "receiver": receiver,
#         "enc": {k:v.hex() for k,v in enc.items()},
#         "sig": sig.hex(),
#         "pk": public_key.decode()
#     }
#     #send message to rabbitmq broker
#     channel.basic_publish(exchange="", routing_key=BROKER_QUEUE,
#                      body=json.dumps(msg).encode())
#     print("[USER] Message sent")

# # ---------------- RECEIVE ----------------
# def receive():
#     def cb(ch, m, p, body):
#         msg = json.loads(body)

#         enc = {k:bytes.fromhex(v) for k,v in msg["enc"].items()}
#         sig = bytes.fromhex(msg["sig"])
#         sender_pk = msg["pk"].encode()

#         plaintext = decrypt_message(enc, enc_keypair, passphrase)

#         if verify_signature(plaintext, sig, sender_pk):
#             print(f"\n[MSG] {plaintext.decode()}")
#         else:
#             print("\n[MSG] INVALID SIGNATURE")


#     channel.basic_consume(queue=queue, on_message_callback=cb, auto_ack=True)
#     channel.start_consuming()

# ---------------- MAIN ----------------
register()
#threading.Thread(target=receive, daemon=True).start()

while True:
    print("\n1. Send message\n2. Exit")
    c = input("> ")
    if c == "1":
        break
        #send_message()
    elif c == "2":
        break
