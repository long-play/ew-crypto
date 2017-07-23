#!/bin/sh

cat src/util.js src/aes.js src/rsa.js src/crypto.js src/export.js > dist/crypto.js
uglifyjs --compress -o dist/crypto.min.js dist/crypto.js

