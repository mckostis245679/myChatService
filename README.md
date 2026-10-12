# myChatService
# myChatService

A simple secure chat application built with Python and RabbitMQ.

## Features

- User registration
- Direct messaging
- RSA and AES encryption
- Digital signatures
- RabbitMQ message routing
- Group broadcasts
- Persistent and transient announcements

## Requirements

- Python 3
- RabbitMQ

Install the required Python packages:

```bash
pip install pika pycryptodomex
```

## Run

Generate the broker keys:

```bash
python broker_keys.py
```

Start the broker:

```bash
python broker.py
```

Then open another terminal and start a user:

```bash
python user.py
```

Run `user.py` in multiple terminals to test communication between users.

## Main Files

- `broker.py` — handles user registration and message routing
- `user.py` — chat client
- `broker_keys.py` — generates broker RSA keys
- `rsa_aes_encrypt_decrypt_sign.py` — handles encryption and signatures

## Technologies

Python, RabbitMQ, RSA, AES
