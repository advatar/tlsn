FROM alpine:3.20

RUN apk add --no-cache openssl

WORKDIR /www

COPY openssl/run.sh /usr/local/bin/run-openssl-fixture
RUN chmod +x /usr/local/bin/run-openssl-fixture

# `-cert` sends only the FIRST certificate in the file, so pointing it at a
# fullchain still presents the leaf alone and the client cannot build a path to
# the CA — it fails the handshake with UnknownIssuer. Intermediates must be
# supplied separately via `-cert_chain`, unlike nginx and httpd which read a
# whole chain from one `ssl_certificate` / `SSLCertificateFile`.
CMD ["/usr/local/bin/run-openssl-fixture"]
