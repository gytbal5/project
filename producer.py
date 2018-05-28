from kafka import KafkaProducer

producer = KafkaProducer(bootstrap_servers='localhost:9092')

for _ in range(1):
    producer.send('my-topic', b"HAY!!!")

producer.close()
