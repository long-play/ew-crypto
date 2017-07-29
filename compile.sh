#!/bin/sh

cat src/util.js src/cbc.js src/gcm.js src/rsa.js src/wcrypto.js src/export.js > dist/crypto.js
uglifyjs --compress -o dist/crypto.min.js dist/crypto.js

