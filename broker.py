import json, pika
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES



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

    session_key = rsa_cipher.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    msg = cipher_aes.decrypt_and_verify(ciphertext, tag)

    msg = json.loads(msg.decode())

    if msg["msgTheme"] == "register":
        if publicKeysDict.get(msg["userName"]) is not None:
            print(f"[BROKER] User {msg['userName']} already registered.")
            send_ack(msg["userQueue"], "Already registered.")
        else:
            publicKeysDict[msg["userName"]] = {
                "userPublicKey": msg["userPublicKey"],
                "userQueue": msg["userQueue"]
            }
            ch.queue_declare(queue=msg["userQueue"], durable=True)
            print(f"[BROKER] Registered {msg['userName']}")
            #save dictionary to file
            with open(STATE_FILE, "w") as f:
                    json.dump(publicKeysDict, f)

            send_ack(msg["userQueue"], "Registration successful.")
    elif msg["msgTheme"] == "request_public_key":
        if msg["receiverName"] in publicKeysDict:
            receiverPK_message = {
                "type": "public_key_response",
                "userPublicKey": publicKeysDict[msg["receiverName"]]["userPublicKey"],
            }
            ch.basic_publish(
                exchange="",
                routing_key=publicKeysDict[msg["senderName"]]["userQueue"],
                body=json.dumps(receiverPK_message).encode()
            )
            print(f"[BROKER] Forwarded message to {msg["senderName"]}")
    elif msg["msgTheme"] == "message_to_receiver":
        if msg["receiverName"] in publicKeysDict:
            ch.basic_publish(
                exchange="",
                routing_key=publicKeysDict[msg["receiverName"]]["userQueue"],
                body=json.dumps(msg["encrypted_for_recipient"]).encode()
            )
            print(f"[BROKER] Forwarded message to {msg["receiverName"]}")

def send_ack(userQueue,msg):
    ack_message = {
        "type": "registration_ack",
        "content": msg
    }
    channel.basic_publish(
        exchange="",
        routing_key=userQueue,
        body=json.dumps(ack_message).encode()
    )


def encrypt_message(original_message):
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(msgBrokerPK)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(original_message)

    package = {
        "enc_session_key": enc_session_key.hex(),
        "nonce": cipher_aes.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }
    return package  



#consume messages from BROKER_QUEUE
channel.basic_consume(queue=BROKER_QUEUE,on_message_callback=callback,auto_ack=True)

print("[BROKER] Running...")
print(publicKeysDict)
channel.start_consuming()