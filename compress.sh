#!/bin/sh

uglifyjs --compress -o dist/crypto.min.js src/util.js src/aes.js src/rsa.js src/crypto.js
