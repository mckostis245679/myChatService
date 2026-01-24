import json
import threading
import time
import pika
import os
from Cryptodome.PublicKey import RSA

from crypto_layer import *
from CH9_HeaderFile         import *

RABBITMQ_HOST = "localhost"
BROKER_QUEUE = "broker_public"


recipient_public_key_cache = {}
userGroup=""  # assigned upon registration

connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
send_channel = connection.channel()

# Load broker public key
msgBrokerPK = RSA.import_key(open("broker_public.pem").read())


print_msg("CLIENT","Login with your username:")
user = input("> ")
user_dir = os.path.join("users", user)
myName, myQueue, myPK, mySK = load_user(user_dir)

def is_signed(encrypted_msg):
    return isinstance(encrypted_msg, dict) and "signature" in encrypted_msg

def is_encrypted(obj) -> bool:
    return (
        isinstance(obj, dict)
        and "enc_session_key" in obj
        and "nonce" in obj
        and "tag" in obj
        and "ciphertext" in obj
    )

def send_message_to_broker(message):
    package = encrypt_message(json.dumps(message).encode('utf-8'), mySK, msgBrokerPK)
    send_channel.basic_publish(exchange="", routing_key=BROKER_QUEUE,
                               body=json.dumps(package).encode())

def register():
    message = {
        "msgTheme": "register",
        "senderName": myName,
        "userPublicKey": myPK.export_key().decode("utf-8"),
        "userQueue": myQueue
    }
    send_message_to_broker(message)

def request_public_key(recipient_username):
    message = {
        "msgTheme": "request_public_key",
        "senderName": myName,
        "recipientName": recipient_username
    }
    send_message_to_broker(message)
    print_msg("CLIENT", f"Requested public key for {recipient_username}")

def create_recipient_msg(recipient_username, recipientPK, msg="Hello!"):
    msgBody = {
        "msgTheme": "message_to_recipient",
        "sender": myName,
        "msg": msg
    }
    encrypted_msgBody = encrypt_message(json.dumps(msgBody).encode('utf-8'), mySK, recipientPK)
    message = {
        "msgTheme": "message_to_recipient",
        "senderName": myName,
        "recipientName": recipient_username,
        "encrypted_for_recipient": encrypted_msgBody
    }
    send_message_to_broker(message)


def message_callback(ch, method, properties, body):
    if is_encrypted(json.loads(body)):
        message, _ = decrypt_message(json.loads(body), mySK)
        message = json.loads(message.decode())
    else:
        message = json.loads(body)

    msg_type = message.get("msgTheme")

    match msg_type:

        case "ACK":
            print_msg("CLIENT", "[ACK] " + message["content"])
            userGroup = message["userGroup"]
            print_msg("CLIENT", f"[USER] Registered in group: {userGroup}")

        case "public_key_response":
            recipientPK = RSA.import_key(message["recipientPublicKey"].encode('utf-8'))
            recipient_public_key_cache[message["recipientName"]] = recipientPK
            print_msg("CLIENT", f"[USER] Public key for {message['recipientName']} cached")

        case "message_to_recipient":
            encryptedMsg = message["encrypted_for_recipient"]
            sender_plain_bytes, sender_signature_hex = decrypt_message(encryptedMsg, mySK)
            senderMsg = json.loads(sender_plain_bytes.decode())
            wait_for_public_key(senderMsg['sender'])
            senderPK = recipient_public_key_cache.get(senderMsg['sender'])

            if is_signed(encryptedMsg):
                if not verify_signature(senderMsg['msg'], sender_signature_hex, senderPK):
                    print_msg("CLIENT", f"[SECURITY] Invalid signature from {senderMsg['sender']}. Dropping message.")
                    return

            print_msg("ALICE", f"[USER] Received message from {senderMsg['sender']}: {senderMsg['msg']}")

        case "announce_transient":
            print_msg("RECEIVER", "[" + message["topic"] + "] Received transient announcement: " + message["announcement"])

        case "announce_persistent":
            print_msg("RECEIVER", "[" + message["topic"] + "] Received persistent announcement: " + message["announcement"])

        case _:
            print_msg("CLIENT", "[USER] Unknown message type received:", msg_type)


def wait_for_public_key(recipient_username, timeout=10):
    request_public_key(recipient_username)
    print_msg("SYSTEM", "[USER] Waiting for public key...")
    wait_time = 0
    while recipient_username not in recipient_public_key_cache and wait_time < 10:
        time.sleep(0.5)
        wait_time += 0.5
    else:
        print_msg("SYSTEM", "[ERROR] Failed to get public key for recipient")

def start_consumer():
    consumer_connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
    channel = consumer_connection.channel()
    channel.queue_declare(queue=myQueue, durable=True)
    channel.basic_consume(queue=myQueue, on_message_callback=message_callback, auto_ack=True)
    print_msg("CLIENT", "[USER] Consumer started, waiting for messages...")
    channel.start_consuming()

# launch consumer thread
consumer_thread = threading.Thread(target=start_consumer, daemon=True)
consumer_thread.start()


register()

# ---------------- Main Loop ----------------
while True:
    print("\nChoose an action:")
    print("1. Wait for messages")
    print("2. Send message to recipient")
    print("3. Send transient announcement to subscribers")
    print("4. Send persistent announcement to subscribers")
    print("5. Send group broadcast to my userGroup")
    print("6. Exit")

    choice = input("> ")

    match choice:

        case "1":
            print_msg("SYSTEM", "[USER] Waiting for messages... Press Enter to return to menu.")
            input()

        case "2":
            recipient_username = input("Enter recipient username:\n> ")

            if recipient_username in recipient_public_key_cache:
                recipientPK = recipient_public_key_cache[recipient_username]
                print_msg("SYSTEM", "[USER] Using cached public key")
            else:
                wait_for_public_key(recipient_username)
                recipientPK = recipient_public_key_cache.get(recipient_username)

            msg = input("Enter your message:\n> ")
            create_recipient_msg(recipient_username, recipientPK, msg)

        case "3":
            topic = input("Select topic to announce to:\n> ")
            announcement = input("Enter your announcement:\n> ")
            msgBody = {
                "msgTheme": "announce_transient",
                "senderName": myName,
                "topic": topic,
                "announcement": announcement
            }
            send_message_to_broker(msgBody)

        case "4":
            topic = input("Select topic to announce to:\n> ")
            announcement = input("Enter your announcement:\n> ")
            msgBody = {
                "msgTheme": "announce_persistent",
                "senderName": myName,
                "topic": topic,
                "body": announcement
            }
            send_message_to_broker(msgBody)

        case "5":
            announcement = input("Enter your announcement:\n> ")
            msgBody = {
                "msgTheme": "group_broadcast",
                "userGroup": userGroup,
                "senderName": myName,
                "body": announcement
            }
            send_message_to_broker(msgBody)

        case "6":
            print_msg("SYSTEM", "[USER] Exiting...")
            connection.close()
            break

        case _:
            print_msg("SYSTEM", "[USER] Invalid choice. Please try again.")
