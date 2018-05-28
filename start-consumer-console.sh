#!/usr/bin/env bash
cd ~/kafka-work
kafka/bin/kafka-console-consumer.sh \
--bootstrap-server localhost:9092 \
--topic my-topic \
--from-beginning
