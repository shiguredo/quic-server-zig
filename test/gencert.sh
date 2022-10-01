#!/bin/bash

set -eu

# Generate a certificate
openssl req -x509 -noenc -days 365 -subj '/C=JP/L=Tokyo/CN=localhost' \
  -newkey ec:<(openssl ecparam -name prime256v1) \
  -sha256 -keyout key.pem -out cert.pem

# Check the generated certificate
openssl x509 -text -noout -in cert.pem

# Turn the certificate and key into the DER format
openssl x509 -outform der -in cert.pem -out cert.der
openssl ec -outform der -in key.pem -out key.der
