# WebRTC server

## Certificate

The certificate in `./static` was generated using the following commands:

```
$ openssl ecparam -name prime256v1 -genkey -noout -out server.pem
$ openssl req -key server.pem -new -subj '/O=Parity/OU=Smoldot' -out server.csr
$ openssl x509 -req -in server.csr -days 3650 -extfile extfile.conf -CA "$(mkcert -CAROOT)/rootCA.pem" -CAkey "$(mkcert -CAROOT)/rootCA-key.pem"  -CAcreateserial -out server.pub.pem
$ openssl pkcs8 -topk8 -nocrypt -in server.pem -out server.private.pem
$ mv server.private.pem server.pem

# Cleanup.
$ rm server.csr

# Calculate sha256 fingerprint of the certificate
$ openssl x509 -noout -fingerprint -sha256 -inform pem -in server.pub.pem
```
