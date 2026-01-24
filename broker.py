import json, pika
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256, TupleHash128
from Cryptodome.Signature import pss
from Cryptodome.Random import get_random_bytes

from crypto_layer import *
from CH9_HeaderFile         import *

connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))
channel = connection.channel()

BROKER_QUEUE = "broker_public"
channel.queue_declare(queue=BROKER_QUEUE, durable=True)

brokerSK = RSA.import_key(open("broker_private.pem","rb").read(),
                             passphrase="brokerpass")
msgBrokerPK = RSA.import_key(open("broker_public.pem").read())

rsa_cipher = PKCS1_OAEP.new(brokerSK)
STATE_FILE = "broker_state.json"

publicKeysDict = {}  # username → {pk, queue}

#load dictionary from file 
with open(STATE_FILE, "r") as f:
    publicKeysDict = json.load(f)

def callback(ch, method, props, body):

    msg, _ = decrypt_message(json.loads(body), brokerSK)
    msg = json.loads(msg.decode())

    userName = msg.get("senderName")
    

    match msg["msgTheme"]:
        case "register":
            if publicKeysDict.get(userName) is not None:
                print_msg("SERVER", f"[BROKER] User {userName} already registered.")
                send_ACK(userName, "Already registered.")
            else:
                publicKeysDict[userName] = {
                    "userPublicKey": msg["userPublicKey"],
                    "userQueue": msg["userQueue"]
                }
                ch.queue_declare(queue=msg["userQueue"], durable=True)

                with open(STATE_FILE, "w") as f:
                    json.dump(publicKeysDict, f)

                print_msg("SERVER", f"[BROKER] Registered {userName}")
                send_ACK(userName, "Registration successful.")

        case "request_public_key":
            if msg["recipientName"] in publicKeysDict:
                recipientPK_message = {
                    "msgTheme": "public_key_response",
                    "recipientPublicKey": publicKeysDict[msg["recipientName"]]["userPublicKey"],
                    "recipientName": msg["recipientName"]
                }
                send_message_to_user(recipientPK_message, userName)
                print_msg("SERVER", f"[BROKER] Sent public key of {msg['recipientName']} to {userName}")

        case "message_to_recipient":
            if msg["recipientName"] in publicKeysDict:
                send_message_to_user(msg, msg["recipientName"])
                print_msg("SERVER", f"[BROKER] Forwarded message to {msg['recipientName']}")

        case "announce_transient":
            topic = msg["topic"]
            subscribe_transient(topic, publicKeysDict[userName]["userQueue"])
            publish_transient(topic, msg)
            print_msg("SERVER", f"[BROKER] Announced transient message on topic: {topic}")

        case "announce_persistent":
            topic = msg["topic"]
            subscribe_persistent(topic, publicKeysDict[userName]["userQueue"])
            publish_persistent(topic, msg)
            print_msg("SERVER", f"[BROKER] Announced persistent message on topic: {topic}")

        case "group_broadcast":
            if msg["userGroup"] == "even_group":
                message = {
                "msgTheme": "transient_announcement",
                "announcement": msg["body"]
                }
                subscribe_transient("even_group", publicKeysDict[userName]["userQueue"])
                publish_transient("even_group", message)
                print_msg("SERVER", f"[BROKER] Announced transient message to even group")
            
            elif msg["userGroup"] == "odd_group":
                message = {
                    "msgTheme": "persistent_announcement",
                    "announcement": msg["body"]
                }
                subscribe_persistent("odd_group", publicKeysDict[userName]["userQueue"])
                publish_persistent("odd_group", message)
                print_msg("SERVER", f"[BROKER] Announced persistent message to odd group")

def send_ACK(userName, content):
    if int(userName[-1], 16) % 2 == 1:
        userGroup="odd_group"
    else:
        userGroup="even_group"

    ack_message = {
        "msgTheme": "ACK",
        "userName": userName,
        "userGroup": userGroup,
        "content": content
    }
    send_message_to_user(ack_message, userName)

def send_message_to_user(message,userName):
    userQueue = publicKeysDict[userName]["userQueue"]
    userPK = RSA.import_key(publicKeysDict[userName]["userPublicKey"])
    
    package = encrypt_message(json.dumps(message).encode('utf-8'), brokerSK, userPK)
    #send message to rabbitmq user
    channel.basic_publish(exchange="", routing_key=userQueue,
                     body=json.dumps(package).encode())
    
def publish_transient( topic, msg):
    message={
        "msgTheme":"announce_transient",
        "topic":topic,
        "announcement":msg["announcement"]
    }
    # Transient: fine to be non-durable
    channel.exchange_declare(exchange=topic, exchange_type='fanout', durable=False)
    channel.basic_publish(
        exchange=topic,
        routing_key='',
        body=json.dumps(message).encode(),
        properties=pika.BasicProperties(delivery_mode=1)  # transient
    )

def publish_persistent( topic, msg):
    message={
        "msgTheme":"announce_persistent",
        "topic":topic,
        "announcement":msg["announcement"]
    }
    # Persistent: exchange durable + message persistent
    channel.exchange_declare(exchange=topic, exchange_type='fanout', durable=True)
    channel.basic_publish(
        exchange=topic,
        routing_key='',
        body=json.dumps(message).encode(),
        properties=pika.BasicProperties(delivery_mode=2)  # persistent
    )

def subscribe_transient( topic, user_queue):
    channel.exchange_declare(exchange=topic, exchange_type='fanout', durable=False)
    channel.queue_bind(exchange=topic, queue=user_queue)

def subscribe_persistent( topic, user_queue):
    channel.exchange_declare(exchange=topic, exchange_type='fanout', durable=True)
    channel.queue_bind(exchange=topic, queue=user_queue)


#consume messages from BROKER_QUEUE
channel.basic_consume(queue=BROKER_QUEUE,on_message_callback=callback,auto_ack=True)

print_msg("SERVER", "[BROKER] Running...")
channel.start_consuming()