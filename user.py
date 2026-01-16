import json, threading
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from crypto_layer import *
import pika
import os
import time


#rabbitmq set up
connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))

send_channel = connection.channel()

BROKER_QUEUE = "broker_public"

msgBrokerPK = RSA.import_key(open("broker_public.pem").read())

receiver_public_key_cache = {}

def callback(ch, method, properties, body):
    message,signature_hex = decrypt_message(json.loads(body), user_dir)
    message=json.loads(message.decode())
    msg_type = message.get("msgTheme")
    
    if msg_type == "registration_ack":
        print("[ACK] " + message["content"])

    elif msg_type == "public_key_response":
        print("[USER] Received public key")
        receiver_public_key = RSA.import_key(message["receiverPublicKey"].encode('utf-8'))
        receiver_public_key_cache[message["receiverName"]] = receiver_public_key
        print(f"[USER] Public key for {message['receiverName']} cached")
    
    elif msg_type == "message_to_receiver":
        encryptedMsg = message["encrypted_for_recipient"]
        
        senderMsg,signature_hex = decrypt_message(encryptedMsg, user_dir)
        senderMsg=json.loads(senderMsg.decode())

        print("[USER] Received message: " + senderMsg["msg"])
    elif msg_type == "transient_announcement":
        print("[USER] Received transient announcement: " + message["announcement"])
    else:
        print("[USER] Unknown message type received.")
        print(msg_type)
        print(message)


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
        "msgTheme": "message_to_receiver",
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
    send_channel.basic_publish(exchange="", routing_key=BROKER_QUEUE,
                     body=json.dumps(package).encode())
    
def start_consumer():
    connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))
    channel = connection.channel()
    channel.queue_declare(queue=myQueue, durable=True)
    channel.basic_consume(queue=myQueue, on_message_callback=callback, auto_ack=True)
    channel.start_consuming()


# ---------------- MAIN ---------------
print("Login with your username:")
user = input("> ")

user_dir = os.path.join("users", user)
myName, myQueue, myPK = load_user(user_dir)

consumer_thread = threading.Thread(target=start_consumer, daemon=True)
consumer_thread.start()
register()
while True:
    print("\nChoose an action: \n" \
    "1. Wait for messages\n" \
    "2. Send message to receiver\n" \
    "3. Send trancient announcement to subscribers\n" \
    "4. Create/Subscribe to trancient announcements\n" \
    "5. Exit")
    choice = input("> ")
    
    if choice == "1":
        print("[USER] Waiting for messages... Press Enter to return to menu.")
        input()
        
    elif choice == "2":
        print("Enter receiver username:")
        receiver_username = input("> ")
        
        # Check if we already have the public key
        if receiver_username in receiver_public_key_cache:
            print("[USER] Using cached public key")
            receiverPK = receiver_public_key_cache[receiver_username]
        else:
            # Request public key first
            print("[USER] Requesting public key...")
            request_receiver_public_key(receiver_username)
            
            # Wait for public key response
            print("[USER] Waiting for public key response...")
            wait_time = 0
            while receiver_username not in receiver_public_key_cache and wait_time < 10:
                time.sleep(0.5)
                wait_time += 0.5
            
            if receiver_username in receiver_public_key_cache:
                receiverPK = receiver_public_key_cache[receiver_username]
            else:
                print("[ERROR] Failed to get public key for receiver")
                continue
        
        print("Enter your message:")
        msg = input("> ")
        
        create_receiver_msg(receiver_username, receiverPK, msg)
        
    elif choice == "3":
        print("Select topic to announce to:")
        topic = input("> ")
        print("Enter your announcement:")
        announcement = input("> ")
        msgBody={
            "msgTheme": "announce_transient",
            "senderName": myName,
            "topic": topic,
            "announcement": announcement
        }
        send_message_to_broker(msgBody)

    elif choice == "4":
        print("Select topic to subscribe to:")
        topic = input("> ")
        msgBody={
            "msgTheme": "subscribe_transient",
            "senderName": myName,
            "topic": topic
        }
        send_message_to_broker(msgBody)

    elif choice == "5":
        print("[USER] Exiting...")
        connection.close()
        break
        
    else:
        print("[USER] Invalid choice. Please try again.")


def connect(queue_name):
    connection = pika.BlockingConnection(pika.ConnectionParameters(host="localhost"))
    channel = connection.channel()
    channel.queue_declare(queue=queue_name)
    return connection, channel

# Λειτουργία αποστολής μηνυμάτων
def send_messages():
    connection, channel = connect()
    while True:
        msg = input("Γράψε μήνυμα (ή 'exit' για έξοδο): ")
        if msg.lower() == 'exit':
            break
        channel.basic_publish(exchange='',
                              routing_key=BROKER_QUEUE,
                              body=msg)
        print(f"[ΑΠΟΣΤΟΛΗ] {msg}")
    connection.close()

# Λειτουργία λήψης μηνυμάτων
def receive_messages():
    connection, channel = connect(BROKER_QUEUE)

    def callback(ch, method, properties, body):
        print(f"[ΛΗΨΗ] {body.decode()}")

    channel.basic_consume(queue=BROKER_QUEUE,
                          on_message_callback=callback,
                          auto_ack=True)
    print("Αναμονή μηνυμάτων... Ctrl+C για έξοδο")
    channel.start_consuming()

# Δημιουργία δύο threads: ένα για αποστολή και ένα για λήψη
if __name__ == "__main__":
    t1 = threading.Thread(target=receive_messages, daemon=True)
    t1.start()

    send_messages()