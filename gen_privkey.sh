#!/bin/sh

openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem 

cat private_key.pem | base64 - -w0
