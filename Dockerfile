FROM golang:alpine AS build-env
RUN apk add -q --update \
    && apk add -q \
            bash \
            git \
            curl \
            g++ \
            libpcap-dev \
    && rm -rf /var/cache/apk/*


RUN go get -u github.com/google/gopacket

COPY gocons.go .
RUN sed -i 's/#cgo linux LDFLAGS: -lpcap/#cgo linux LDFLAGS: \/usr\/lib\/libpcap.a/g' src/github.com/google/gopacket/pcap/pcap.go
RUN go build -o gocons .

# final stage
FROM alpine
WORKDIR /app
COPY --from=build-env /go/gocons /app/
CMD ./gocons
