#!/usr/bin/env bash
cd ~/kafka-work
kafka/bin/kafka-console-producer.sh \
--broker-list localhost:9092 \
--topic my-topic
