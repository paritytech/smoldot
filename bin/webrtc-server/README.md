# WebRTC server

## Certificate

The certificate in `./static` was generated using the following commands:

```
# Extensions required for certificate validation.
$ EXTFILE='extfile.conf'
$ echo 'subjectAltName = DNS:parity.io' > "${EXTFILE}"

$ SERVER_NAME='server'
$ openssl ecparam -name prime256v1 -genkey -noout -out "${SERVER_NAME}.pem"
$ openssl req -key "${SERVER_NAME}.pem" -new -sha256 -subj '/C=NL' -out "${SERVER_NAME}.csr"
$ openssl x509 -req -in "${SERVER_NAME}.csr" -days 365 -extfile "${EXTFILE}" -signkey "${SERVER_NAME}.pem" -sha256 -out "${SERVER_NAME}.pub.pem"
$ openssl pkcs8 -topk8 -nocrypt -in server.pem -out server.private.pem
$ mv server.private.pem server.pem

# Cleanup.
$ rm "${EXTFILE}" "${SERVER_NAME}.csr"

# Calculate sha256 fingerprint of the certificate
$ openssl x509 -noout -fingerprint -sha256 -inform pem -in server.pub.pem
```
