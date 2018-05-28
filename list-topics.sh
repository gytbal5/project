#!/usr/bin/env bash
cd ~/kafka-work
# list existing topics
kafka/bin/kafka-topics.sh --list \
--zookeeper localhost:2181
