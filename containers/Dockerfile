FROM golang:1.20-buster as builder
RUN mkdir /build
WORKDIR /build
RUN mkdir bin gopath
ENV GOPATH /build/gopath
ADD . /build/gopath/src/github.com/mozilla/OneCRL-Tools/

WORKDIR /build/gopath/src/github.com/mozilla/OneCRL-Tools/ccadb2OneCRL
RUN CGO_ENABLED=0 go build -o /build/bin/ccadb2OneCRL
WORKDIR /build

FROM alpine:3
RUN apk add --no-cache ca-certificates

RUN adduser -S -u 10001 -h /app app

COPY --from=builder /build/bin /app/
ADD version.json /app/

# Don't have any default configuration; leave it to the Docker runner
RUN echo "# Deliberately empty default config file" > /app/config.env

USER app
WORKDIR /app

CMD [ "/app/ccadb2OneCRL" ]
