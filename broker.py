import json, pika
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256, TupleHash128
from Cryptodome.Signature import pss
from Cryptodome.Random import get_random_bytes

connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))
channel = connection.channel()

BROKER_QUEUE = "broker_public"
channel.queue_declare(queue=BROKER_QUEUE, durable=True)

private_key = RSA.import_key(open("broker_private.pem","rb").read(),
                             passphrase="brokerpass")
msgBrokerPK = RSA.import_key(open("broker_public.pem").read())

rsa_cipher = PKCS1_OAEP.new(private_key)

STATE_FILE = "broker_state.json"

publicKeysDict = {}  # username → {pk, queue}
#load dictionary from file 
with open(STATE_FILE, "r") as f:
    publicKeysDict = json.load(f)

def callback(ch, method, props, body):
    package = json.loads(body)
    
    enc_session_key = bytes.fromhex(package["enc_session_key"])
    nonce = bytes.fromhex(package["nonce"])
    ciphertext = bytes.fromhex(package["ciphertext"])
    tag = bytes.fromhex(package["tag"])
    signature = bytes.fromhex(package["signature"])

    session_key = rsa_cipher.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted_payload = cipher_aes.decrypt_and_verify(ciphertext, tag)
    msg = json.loads(decrypted_payload.decode('utf-8'))

    # Get user name and check if they exist
    user_name = msg.get("userName")

    if msg["msgTheme"] == "register":
        if publicKeysDict.get(user_name) is not None:
            print(f"[BROKER] User {user_name} already registered.")
            send_ack(user_name, "Already registered.")
        else:
            # Store user's public key before proceeding
            publicKeysDict[user_name] = {
                "userPublicKey": msg["userPublicKey"],
                "userQueue": msg["userQueue"]
            }
            ch.queue_declare(queue=msg["userQueue"], durable=True)
            print(f"[BROKER] Registered {user_name}")
            
            with open(STATE_FILE, "w") as f:
                json.dump(publicKeysDict, f)
            
            send_ack(user_name, "Registration successful.")
        return

    user_name = msg.get("senderName")
    sender_PK_pem = publicKeysDict[user_name]["userPublicKey"]
    sender_PK = RSA.import_key(sender_PK_pem)

    h = SHA256.new(decrypted_payload)
    verifier = pss.new(sender_PK)
    
    try:
        verifier.verify(h, signature)
        print(f"[BROKER] Signature for {user_name} is authentic.")
    except (ValueError, TypeError):
        print("[BROKER] Signature verification failed!")

    if msg["msgTheme"] == "request_public_key":
        if msg["receiverName"] in publicKeysDict:
            receiverPK_message = {
                "msgTheme": "public_key_response",
                "receiverPublicKey": publicKeysDict[msg["receiverName"]]["userPublicKey"],
                "receiverName": msg["receiverName"]
            }
            send_message_to_user(receiverPK_message, user_name)
            print(f"[BROKER] Sent public key of {msg['receiverName']} to {user_name}")
    
    elif msg["msgTheme"] == "message_to_receiver":
        if msg["receiverName"] in publicKeysDict:
            send_message_to_user(msg,msg["receiverName"])
            print(f"[BROKER] Forwarded message to {msg["receiverName"]}")

    elif msg["msgTheme"] == "announce_transient":
        topic = msg["topic"]
        message={
            "msgTheme":"transient_announcement",
            "announcement":msg["announcement"]
        }
        encrypted_message=encrypt_message(json.dumps(message).encode('utf-8'),msgBrokerPK)
        
        channel.exchange_declare(exchange=topic, exchange_type='fanout')
        channel.basic_publish(
            exchange=topic,
            routing_key='',
            body=json.dumps(encrypted_message).encode()
        )
        print(f"[BROKER] Announced transient message on topic: {topic}")
    
    elif msg["msgTheme"] == "subscribe_transient":
        topic = msg["topic"]
        channel.exchange_declare(exchange=topic, exchange_type='fanout')
        channel.queue_bind(
            exchange=topic,
            queue=publicKeysDict[user_name]["userQueue"]
        )
        print(f"[BROKER] {user_name} subscribed to transient topic: {topic}")



def send_ack(userName,msg):
    ack_message = {
        "msgTheme": "registration_ack",
        "content": msg
    }
    send_message_to_user(ack_message,userName)

def send_message_to_user(message,userName):
    userQueue = publicKeysDict[userName]["userQueue"]
    userPK = RSA.import_key(publicKeysDict[userName]["userPublicKey"])
    
    package = encrypt_message(json.dumps(message).encode('utf-8'),userPK)
    #send message to rabbitmq user
    channel.basic_publish(exchange="", routing_key=userQueue,
                     body=json.dumps(package).encode())
    

def encrypt_message(original_message, PK):
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(PK)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(original_message)

    mySK = RSA.import_key(open("broker_private.pem","rb").read(),
                             passphrase="brokerpass")
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



#consume messages from BROKER_QUEUE
channel.basic_consume(queue=BROKER_QUEUE,on_message_callback=callback,auto_ack=True)

print("[BROKER] Running...")
channel.start_consuming()