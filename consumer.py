from kafka import KafkaConsumer
import time

consumer = KafkaConsumer(bootstrap_servers='localhost:9092', auto_offset_reset='earliest', consumer_timeout_ms=1000)
consumer.subscribe(['my-topic'])

for m in consumer:
    print(m)
    time.sleep(0.02)

consumer.close()
