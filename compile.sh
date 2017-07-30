#!/bin/sh

cat src/util.js src/cbc.js src/gcm.js src/rsa.js src/wcrypto.js src/export.js > dist/wcrypto.js
uglifyjs --compress -o dist/wcrypto.min.js dist/wcrypto.js

