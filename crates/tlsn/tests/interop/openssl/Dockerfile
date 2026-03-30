FROM alpine:3.20

RUN apk add --no-cache openssl

CMD ["sh", "-c", "openssl s_server -accept 443 -www -tls1_3 -cert /certs/rsa/end.fullchain -key /certs/rsa/end.key"]
