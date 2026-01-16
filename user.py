import json, threading
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from crypto_layer import *
import pika
import os



#rabbitmq set up
connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))
channel = connection.channel()

BROKER_QUEUE = "broker_public"

msgBrokerPK = RSA.import_key(open("broker_public.pem").read())

# ---------------- REGISTER ----------------
def register():
    message = {
        "msgTheme": "register",
        "userName": myName,
        "userPublicKey": myPK.decode('utf-8'),
        "userQueue": myQueue
    }
    send_message_to_broker(message)
    print("[USER] Registered")

def callback(ch, method, properties, body):
    message = json.loads(body)
    msg_type = message.get("type")
    
    if msg_type == "registration_ack":
        print("[ACK] " + message["content"])
    elif msg_type == "public_key_response":
        print("[USER] Received public key")
        receiver_public_key = RSA.import_key(message["userPublicKey"].encode('utf-8'))

        create_receiver_msg("75dc1208acd3a807",receiver_public_key)
    elif msg_type == "message_to_receiver":
        print("[USER] Received message: " + decrypted_msg["msg"])
        encrypted_msg = message["encrypted_for_recipient"]
        decrypted_msg = decrypt_message(encrypted_msg, user_dir)
    else:
        print("[USER] Unknown message type received.")
        print(msg_type)
        print(message)
def request_receiver_public_key(receiver_username):
    request_message = {
        "msgTheme": "request_public_key",
        "senderName": myName,
        "receiverName": receiver_username
    }
    send_message_to_broker(request_message)
    print("[USER] Requested public key for " + receiver_username)

def create_receiver_msg(receiver_username,receiverPK,msg="Hello, this is a test message."):
    msgBody={
        "type": "message_to_receiver",
        "sender": myName,
        "msg": msg
    }
    encrypted_msgBody= encrypt_message(json.dumps(msgBody).encode('utf-8'), user_dir,receiverPK)
    message = {
        "msgTheme": "message_to_receiver",
        "senderName": myName,
        "receiverName": receiver_username,
        "encrypted_for_recipient": encrypted_msgBody
    }
    send_message_to_broker(message)

def send_message_to_broker(message):

    package = encrypt_message(json.dumps(message).encode('utf-8'), user_dir,msgBrokerPK)

    #send message to rabbitmq broker
    channel.basic_publish(exchange="", routing_key=BROKER_QUEUE,
                     body=json.dumps(package).encode())



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

# ---------------- MAIN ---------------
print("Login with your username:")
user = input("> ")

user_dir = os.path.join("users", user)
myName, myQueue, myPK = load_user(user_dir)
print(f"[USER] username = {myName}")
register()
#create a unique queue for the user
channel.queue_declare(queue=myQueue, durable=True)
channel.basic_consume(queue=myQueue,on_message_callback=callback,auto_ack=True)
if user == "mike":
    channel.start_consuming()
else:
    request_receiver_public_key("75dc1208acd3a807")
    channel.start_consuming()




