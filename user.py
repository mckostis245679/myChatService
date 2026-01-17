import json
import threading
import time
import os
from Cryptodome.PublicKey import RSA
from crypto_layer import *
import pika

RABBITMQ_HOST = "localhost"
BROKER_QUEUE = "broker_public"


receiver_public_key_cache = {}


connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
send_channel = connection.channel()

# Load broker public key
msgBrokerPK = RSA.import_key(open("broker_public.pem").read())


print("Login with your username:")
user = input("> ")
user_dir = os.path.join("users", user)
myName, myQueue, myPK = load_user(user_dir)

def send_message_to_broker(message):
    package = encrypt_message(json.dumps(message).encode('utf-8'), user_dir, msgBrokerPK)
    send_channel.basic_publish(exchange="", routing_key=BROKER_QUEUE,
                               body=json.dumps(package).encode())

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
    message = {
        "msgTheme": "request_public_key",
        "senderName": myName,
        "receiverName": receiver_username
    }
    send_message_to_broker(message)
    print(f"[USER] Requested public key for {receiver_username}")

def create_receiver_msg(receiver_username, receiverPK, msg="Hello!"):
    msgBody = {
        "msgTheme": "message_to_receiver",
        "sender": myName,
        "msg": msg
    }
    encrypted_msgBody = encrypt_message(json.dumps(msgBody).encode('utf-8'), user_dir, receiverPK)
    message = {
        "msgTheme": "message_to_receiver",
        "senderName": myName,
        "receiverName": receiver_username,
        "encrypted_for_recipient": encrypted_msgBody
    }
    send_message_to_broker(message)


def message_callback(ch, method, properties, body):
    message, _ = decrypt_message(json.loads(body), user_dir)
    message = json.loads(message.decode())
    msg_type = message.get("msgTheme")

    if msg_type == "registration_ack":
        print("[ACK] " + message["content"])

    elif msg_type == "public_key_response":
        receiverPK = RSA.import_key(message["receiverPublicKey"].encode('utf-8'))
        receiver_public_key_cache[message["receiverName"]] = receiverPK
        print(f"[USER] Public key for {message['receiverName']} cached")

    elif msg_type == "message_to_receiver":
        encryptedMsg = message["encrypted_for_recipient"]
        senderMsg, _ = decrypt_message(encryptedMsg, user_dir)
        senderMsg = json.loads(senderMsg.decode())
        print(f"[USER] Received message from {senderMsg['sender']}: {senderMsg['msg']}")

    elif msg_type == "transient_announcement":
        print("[USER] Received transient announcement: " + message["announcement"])

    else:
        print("[USER] Unknown message type received:", msg_type)

def start_consumer():
    consumer_connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
    channel = consumer_connection.channel()
    channel.queue_declare(queue=myQueue, durable=True)
    channel.basic_consume(queue=myQueue, on_message_callback=message_callback, auto_ack=True)
    print("[USER] Consumer started, waiting for messages...")
    channel.start_consuming()

# launch consumer thread
consumer_thread = threading.Thread(target=start_consumer, daemon=True)
consumer_thread.start()


register()

# ---------------- Main Loop ----------------
while True:
    print("\nChoose an action:")
    print("1. Wait for messages")
    print("2. Send message to receiver")
    print("3. Send transient announcement to subscribers")
    print("4. Subscribe to transient announcements")
    print("5. Send persistent announcement to subscribers")
    print("6. Subscribe to persistent announcements")
    print("7.Send transient announcement to evenGroup")
    print("8.Send persistent announcement to oddGroup")
    print("9. Exit")

    choice = input("> ")

    if choice == "1":
        print("[USER] Waiting for messages... Press Enter to return to menu.")
        input()

    elif choice == "2":
        receiver_username = input("Enter receiver username:\n> ")

        # Use cached public key if available, otherwise request
        if receiver_username in receiver_public_key_cache:
            receiverPK = receiver_public_key_cache[receiver_username]
            print("[USER] Using cached public key")
        else:
            request_receiver_public_key(receiver_username)
            print("[USER] Waiting for public key...")
            wait_time = 0
            while receiver_username not in receiver_public_key_cache and wait_time < 10:
                time.sleep(0.5)
                wait_time += 0.5
            if receiver_username in receiver_public_key_cache:
                receiverPK = receiver_public_key_cache[receiver_username]
            else:
                print("[ERROR] Failed to get public key for receiver")
                continue

        msg = input("Enter your message:\n> ")
        create_receiver_msg(receiver_username, receiverPK, msg)

    elif choice == "3":
        topic = input("Select topic to announce to:\n> ")
        announcement = input("Enter your announcement:\n> ")
        msgBody = {
            "msgTheme": "announce_transient",
            "senderName": myName,
            "topic": topic,
            "announcement": announcement
        }
        send_message_to_broker(msgBody)

    elif choice == "4":
        topic = input("Select topic to subscribe to:\n> ")
        msgBody = {
            "msgTheme": "subscribe_transient",
            "senderName": myName,
            "topic": topic
        }
        send_message_to_broker(msgBody)
    elif choice == "5":
        topic = input("Select topic to announce to:\n> ")
        announcement = input("Enter your announcement:\n> ")
        msgBody = {
            "msgTheme": "announce_persistent",
            "senderName": myName,
            "topic": topic,
            "announcement": announcement
        }
        send_message_to_broker(msgBody)

    elif choice == "6":
        topic = input("Select topic to subscribe to:\n> ")
        msgBody = {
            "msgTheme": "subscribe_persistent",
            "senderName": myName,
            "topic": topic
        }
        send_message_to_broker(msgBody)
    elif choice == "7":
        announcement = input("Enter your announcement:\n> ")
        msgBody = {
            "msgTheme": "announce_evenGroup",
            "senderName": myName,
            "announcement": announcement
        }
        send_message_to_broker(msgBody)

    elif choice == "8":
        announcement = input("Enter your announcement:\n> ")
        msgBody = {
            "msgTheme": "announce_oddGroup",
            "senderName": myName,
            "announcement": announcement
        }
        send_message_to_broker(msgBody)
    elif choice == "9":
        print("[USER] Exiting...")
        connection.close()
        break

    else:
        print("[USER] Invalid choice. Please try again.")
