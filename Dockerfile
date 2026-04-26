FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY . .
RUN go build -mod=vendor -o pia-wg-config .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /src/pia-wg-config /usr/local/bin/pia-wg-config
RUN chmod +x /usr/local/bin/pia-wg-config

ENTRYPOINT ["/usr/local/bin/pia-wg-config"]
