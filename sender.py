import pika
import sys

# 1. Establish a connection to RabbitMQ server running on localhost
connection = pika.BlockingConnection(
    pika.ConnectionParameters(host='localhost'))
channel = connection.channel()

# 2. Declare a fanout exchange named 'logs'
# Fanout exchange broadcasts all messages to all queues it knows
channel.exchange_declare(exchange='logs', exchange_type='fanout')

# 3. Prepare the message:
# - Take command line arguments after script name, join them into a string
# - If no arguments provided, use default message
message = ''.join(sys.argv[1:]) or "info: Hello World!"

# 4. Publish the message to the 'logs' exchange
# routing_key is empty for fanout exchanges
channel.basic_publish(exchange='logs', routing_key='', body=message)

# 5. Print confirmation
print(message)

# 6. Close the connection
connection.close()