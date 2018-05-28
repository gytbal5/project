# kafka server init...
import sys, os, time, subprocess, shlex

"""os.system('sh run-zookeeper.sh')
#time.sleep(10)
os.system('sh run-kafka.sh')"""

"""subprocess.call(shlex.split('PycharmProjects/PROJECT/kafka-work/run-zookeeper.sh'))
time.sleep(10)
subprocess.call(shlex.split('PycharmProjects/PROJECT/kafka-work/run-kafka.sh'))"""

"""subprocess.call(shlex.split('sh run-zookeeper.sh'))
time.sleep(10)
subprocess.call(shlex.split('sh run-kafka.sh'))"""

# need to make alias...
""""subprocess.call('zookeeper-run-alias')
time.sleep(10)
subprocess.call('kafka-run-alias')"""""

subprocess.call(['sh run-zookeeper.sh'])
time.sleep(10)
subprocess.call(['./run-kafka.sh'])