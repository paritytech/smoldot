# WebRTC server

## Install

The certificate in `./static` directory **MUST** be marked as trusted (Chrome:
'Security and privacy' -> 'Security' -> 'Manage certificates').

You are welcome to use the certificate in `./static`. There's nothing more to
do in that case!

The certificate and key were generated using the following commands:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out smoldot.pem
openssl req -key smoldot.pem -new -subj '/O=Parity/OU=Smoldot' -out smoldot.csr
openssl x509 -req -in smoldot.csr -days 3650 -extfile extfile.conf -signkey smoldot.pem -out smoldot.crt
openssl pkcs8 -topk8 -nocrypt -in smoldot.pem -out smoldot.private.pem
mv smoldot.private.pem smoldot.key

# Cleanup.
rm smoldot.csr smoldot.pem

# Calculate sha256 fingerprint of the certificate
# Don't forget to update one used in the client
openssl x509 -noout -fingerprint -sha256 -inform pem -in smoldot.crt
```

Alternatively, you can use [certstrap](https://github.com/square/certstrap) to
generate a CA and a certificate:

```sh
certstrap init --common-name CertAuth --curve P-256
certstrap request-cert --common-name smoldot -ip 127.0.0.1,0:0:0:0:0:0:0:1 -domain localhost -curve P-256
certstrap sign smoldot --CA CertAuth

# Calculate sha256 fingerprint of the certificate
# Don't forget to update one used in the client
openssl x509 -noout -fingerprint -sha256 -inform pem -in smoldot.crt
```

You will need to mark the CA as trusted ('System' in Keychain on Mac).

## Run

```sh
# ipv4
./webrtc-server -l 127.0.0.1:41000 --debug

# ipv6
./webrtc-server -l ::1:41000 --debug
```
