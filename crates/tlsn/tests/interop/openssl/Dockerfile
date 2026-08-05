FROM alpine:3.20

RUN apk add --no-cache openssl

# `-cert` sends only the FIRST certificate in the file, so pointing it at a
# fullchain still presents the leaf alone and the client cannot build a path to
# the CA — it fails the handshake with UnknownIssuer. Intermediates must be
# supplied separately via `-cert_chain`, unlike nginx and httpd which read a
# whole chain from one `ssl_certificate` / `SSLCertificateFile`.
CMD ["sh", "-c", "openssl s_server -accept 443 -www -tls1_3 -cert /certs/rsa/end.cert -key /certs/rsa/end.key -cert_chain /certs/rsa/end.chain"]
