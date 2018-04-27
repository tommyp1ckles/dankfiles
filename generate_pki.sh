#!/bin/bash

echo "Creating PKI for: ${1}"

echo "Generating Key-Pair"
openssl req \
       -newkey rsa:2048 -nodes -keyout ${1}.key \
       -x509 -days 365 -out ${1}.crt
