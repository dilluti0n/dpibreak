#!/bin/sh
#
# local https server test
#     ip netns exec srv tcpdump -ni veth-s -vv 'tcp port 443'
#     dpibreak -a --log-level debug
#     curl -vk https://10.99.0.2/

ip netns add srv
ip link add veth-h type veth peer name veth-s
ip link set veth-s netns srv
ip addr add 10.99.0.1/24 dev veth-h && ip link set veth-h up
ip -n srv addr add 10.99.0.2/24 dev veth-s
ip -n srv link set veth-s up && ip -n srv link set lo up

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=test \
    -keyout /tmp/k.pem -out /tmp/c.pem
ip netns exec srv openssl s_server -accept 443 -cert /tmp/c.pem -key /tmp/k.pem -www
