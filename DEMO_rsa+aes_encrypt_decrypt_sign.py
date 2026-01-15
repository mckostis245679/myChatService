from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey   import RSA
from Cryptodome.Hash        import TupleHash128
from Cryptodome.Random      import get_random_bytes
from Cryptodome.Cipher      import AES, PKCS1_OAEP

from CH9_HeaderFile         import *

screen_clear()

### [A] OWNER GENERATES A NEW RSA KEY-PAIR, ENCRYPTS IT AND THEN STORES IT IN A LOCAL FILE...
secret_code = "owner_secret_passphrase"

# [A.1] ...RSA-KEY PAIR GENERATION...
new_RSA_key_pair = RSA.generate(2048)

#[A.2] OWNER ENCRYPTS RSA-KEY PAIR...
encrypted_RSA_key_pair = new_RSA_key_pair.export_key(   passphrase=secret_code, pkcs=8,
                                                        protection="scryptAndAES128-CBC",
                                                        prot_params={'iteration_count':131072}  )

#[A.3] OWNER LOCALLY STORES ENCRYPTED RSA-KEY PAIR ...
with open("./rsa_key.bin", "wb") as f:
    f.write(encrypted_RSA_key_pair)

#[A.3] OWNER LOCALLY STORES PRIVATE AND PUBLIC RSA-KEYS, IN SEPARATE LOCAL FILES ...

# ... extraction of private key from RSA-KEY pair ...
new_RSA_private_key = new_RSA_key_pair.export_key()
print_msg("OWNER",f'''
[OWNER]     My new RSA private key is:\n{bcolors.MSG}{new_RSA_private_key.decode('utf-8')}''')

# ... extraction of public key from RSA-KEY pair ...
new_RSA_public_key = new_RSA_key_pair.publickey().export_key()
print_msg("OWNER",f'''
[OWNER]     My new RSA public key to store at local file:\n{bcolors.MSG}{new_RSA_public_key.decode('utf-8')}''')

# ... creation of a HEX-printable username (string) from RSA public key ...
PublicKeyHash = TupleHash128.new(digest_bytes=8)
PublicKeyHash.update(new_RSA_public_key)
new_username = PublicKeyHash.hexdigest()
print_msg("OWNER",f'''
[OWNER]     My new username is:
            {bcolors.RED}{new_username}''')

PrivateKeyHash = TupleHash128.new(digest_bytes=32)
PrivateKeyHash.update(new_RSA_private_key)
new_hiddenInboxQueue = PrivateKeyHash.hexdigest()
print_msg("OWNER",f'''
[OWNER]     The name of my secret RabbitMQ inbox is:
            {bcolors.RED}{new_hiddenInboxQueue}''')

print_msg("OWNER",f'''
[OWNER]     I will now store my RSA keys, my username and the name 
            of the secret  queue for my inbox in separate files:
''')

with open("./rsa_private.pem", "wb") as f:
    f.write(new_RSA_private_key)

with open("./rsa_public.pem", "wb") as f:
    f.write(new_RSA_public_key)

with open("./rsa_username.pem", "w") as f:
    f.write(new_username)

with open("./rsa_userqueue.pem", "w") as f:
    f.write(new_hiddenInboxQueue)

### [B] LOAD AN RSA-KEY PAIR FROM AN ENCRYPTED LOCAL FILE...  
encrypted_RSA_key_pair = open("./rsa_key.bin", "rb").read()
my_RSA_key_pair = RSA.import_key(encrypted_RSA_key_pair, passphrase=secret_code)

my_RSA_private_key = my_RSA_key_pair.export_key()
print_msg("OWNER",f'''
[OWNER]     My RSA private key recovered from local file:\n{bcolors.MSG}{my_RSA_private_key.decode('utf-8')}''')

my_RSA_public_key = my_RSA_key_pair.publickey().export_key()
print_msg("OWNER",f'''
[OWNER]     RSA public key recovered from local file:\n{bcolors.MSG}{my_RSA_public_key.decode('utf-8')}''')

if (my_RSA_public_key == new_RSA_public_key) and (my_RSA_private_key == new_RSA_private_key):
    print_msg("OWNER",'''
[OWNER]     ALL GOOD: Original and locally retrieved public key match.''')
    
else:
    print_msg("ERROR",'''
[OWNER]     ERROR: Original and locally retrieved public key DO NOT match.''')

### [C] SENDER RSA-ENCRYPTS A MESSAGE WITH RECIPIENT'S PUBLIC KEY, LOADED FROM A LOCAL FILE...
original_message = b'''
# ===============================================================================
# CEID_NE4117 (2025-26) :: LAB-2 --> myChat SERVICE 
#                          DEMO :: RSA-based encryption / decryption / signing
# -------------------------------------------------------------------------------
# TASK: (1) RSA+AES encryption of original message, using RSA keys 
#           and temporally created AES session key
#       (2) RSA-signing of original message
#       (3) Decryption of encrypted message using and verification of 
# ==============================================================================='''

#print_msg("SENDER",f"\n[SENDER]\tI will RSA+AES encrypt and store to a local file\n\t\tthe following message for the RECEIVER:{original_message.decode('utf-8')}")
print_msg("SENDER",f'''
[SENDER]    I will RSA+AES encrypt the following message for the RECEIVER:{bcolors.MSG}{original_message.decode('utf-8')}
''')

# [C.1] SENDER READS RECVEIVER'S RSA-PUBLIC-KEY FROM LOCAL FILE...
recipient_public_key = RSA.import_key(open("./rsa_public.pem").read())

# [C.2] SENDER PREPARES A RANDOM SESSION KEY, AND ENCRYPTS IT WITH RECEIVER'S RSA-PUBLIC-KEY 
session_key = get_random_bytes(16)
cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(original_message)

# [C.3] SENDER SIGNS ORIGINAL MESSAGE WITH HER RSA-PRIVATE-KEY 
print_msg("SENDER",f'''
[SENDER]    I will create an RSA-signature of my message.
''')

sender_private_key = RSA.import_key(open("./rsa_private.pem",'rb').read())
h = SHA256.new(original_message)
original_message_signature = pss.new(sender_private_key).sign(h)

# [C.4] SENDER SUBMITS THE ENCRYPTED DATA AND THE SIGNATURE OF ORIGINAL MESSAGE 

print_msg("SENDER",f'''
[SENDER]    I will store the encrypted message and the signature in separate local files.
''')

with open("encrypted_data.bin", "wb") as f:
    f.write(enc_session_key)
    f.write(cipher_aes.nonce)
    f.write(tag)
    f.write(ciphertext)

with open("msg_signature.bin", "wb") as f:
    f.write(original_message_signature)

### [D] RECEIVER RSA-DECRYPTS AN ENCRYPTED MESSAGE WITH RSA+AES...

# [D.1] RECEIVER LOADS HER RSA-PRIVATE-KEY FROM A LOCAL FILE...

# [D.1.a] ...from ENCRYPTED rsa_key.bin file...     (RECOMMENDED)
encrypted_RSA_key_pair      = open("./rsa_key.bin", "rb").read()
recipient_RSA_key_pair      = RSA.import_key(encrypted_RSA_key_pair, passphrase=secret_code)
recipient_RSA_private_key   = RSA.import_key(recipient_RSA_key_pair.export_key())

# [D.1.b] ...from ORIGINAL rsa_private.pem file...  (NOT RECOMMENDED)
#recipient_RSA_private_key  = RSA.import_key(open("./rsa_private.pem").read())

# [D.2] RECEIVER OPENS THE FILE WITH RSA+AES ENCRYPTED MESSAGE...
with open("./encrypted_data.bin", "rb") as f:
    enc_session_key = f.read(recipient_RSA_private_key.size_in_bytes())
    nonce           = f.read(16)
    tag             = f.read(16)
    ciphertext      = f.read()

# [D.3] RECEIVER DECRYPTS AES SESSION KEY WITH HER RSA-PRIVATE-KEY...
cipher_rsa          = PKCS1_OAEP.new(recipient_RSA_private_key)
session_key         = cipher_rsa.decrypt(enc_session_key)

# [D.4] RECEIVER DECRYPTS ORIGINAL MESSAGE WITH AES SESSION KEY...
cipher_aes          = AES.new(session_key, AES.MODE_EAX, nonce)
decrypted_message   = cipher_aes.decrypt_and_verify(ciphertext, tag)
print_msg("RECEIVER",f'''
[RECEIVER]  I recovered from a local file and RSA+AES decrypted
            the following message from the SENDER:{bcolors.MSG}{decrypted_message.decode('utf-8')}
''')

with open("./msg_signature.bin", "rb") as f:
    sender_signature = f.read()
print_msg("RECEIVER",f'''
[RECEIVER]  I recovered from a local file the SENDER's signature and I will now verify it.
''')

sender_public_key = RSA.import_key(open("./rsa_public.pem",'rb').read())
h = SHA256.new(decrypted_message)

verifier = pss.new(sender_public_key)

try:
    verifier.verify(h, sender_signature)
    print_msg("RECEIVER",f'''
[RECEIVER]  The SENDER's signature {bcolors.HIGHLIGHT}is authentic{bcolors.ENDC}{bcolors.RECEIVER}.
''')

except (ValueError):
    print_msg("RECEIVER",f'''
[RECEIVER] The SENDER's signature {bcolors.HIGHLIGHT}{bcolors.RED}is not authentic{bcolors.ENDC}{bcolors.RECEIVER}.
''')