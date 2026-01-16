import pika
import sys

# 1. Establish a connection to RabbitMQ server running on localhost
connection = pika.BlockingConnection(
    pika.ConnectionParameters(host='localhost'))
channel = connection.channel()

# 2. Declare a fanout exchange named 'logs'
# Fanout exchange broadcasts all messages to all queues it knows
channel.exchange_declare(exchange='logs', exchange_type='fanout')


result=channel.queue_declare('', exclusive=True)
queue_name=result.method.queue

channel.queue_bind(exchange='logs', queue=queue_name)


def callback(ch, method, properties, body): 
    print( body)

channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)

channel.start_consuming()