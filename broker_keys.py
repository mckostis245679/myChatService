from Cryptodome.PublicKey import RSA

key = RSA.generate(2048)

with open("broker_private.pem", "wb") as f:
    f.write(key.export_key(passphrase="brokerpass", pkcs=8,
            protection="scryptAndAES128-CBC"))

with open("broker_public.pem", "wb") as f:
    f.write(key.publickey().export_key())
