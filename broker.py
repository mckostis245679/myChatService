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

rsa_cipher = PKCS1_OAEP.new(private_key)
publicKeysDict = {}  # username → {pk, queue}

def decrypt(data):
    return PKCS1_OAEP.new(private_key).decrypt(data)


def callback(ch, method, props, body):
    package = json.loads(body)

    enc_session_key = rsa_cipher.decrypt(bytes.fromhex(package["enc_session_key"]))
    cipher_aes = AES.new(enc_session_key, AES.MODE_EAX,
                            bytes.fromhex(package["nonce"]))
    ciphertext = cipher_aes.decrypt_and_verify(
        bytes.fromhex(package["ciphertext"]),
        bytes.fromhex(package["tag"])
    )
    msg = json.loads(ciphertext.decode())

    if msg["type"] == "register":
        publicKeysDict[msg["userName"]] = {
            "userPublicKey": msg["userPublicKey"],
            "userQueue": msg["userQueue"]
        }
        ch.queue_declare(queue=msg["userQueue"], durable=True)
        print(f"[BROKER] Registered {msg['userName']}")

    elif msg["type"] == "send":
        receiver = msg["receiver"]
        if receiver in publicKeysDict:
            ch.basic_publish(
                exchange="",
                routing_key=publicKeysDict[receiver]["queue"],
                body=json.dumps(msg).encode()
            )
            print(f"[BROKER] Forwarded message to {receiver}")

#consume messages from BROKER_QUEUE
channel.basic_consume(queue=BROKER_QUEUE,on_message_callback=callback,auto_ack=True)

print("[BROKER] Running...")
channel.start_consuming()