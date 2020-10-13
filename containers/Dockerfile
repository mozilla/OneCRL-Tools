FROM golang:1.15-buster as builder
RUN mkdir /build
WORKDIR /build
RUN mkdir bin gopath
ENV GOPATH /build/gopath
ADD . /build/gopath/src/github.com/mozilla/OneCRL-Tools/

RUN go get github.com/mozilla/OneCRL-Tools/ccadb2OneCRL
RUN CGO_ENABLED=0 go build -o bin/ccadb2OneCRL github.com/mozilla/OneCRL-Tools/ccadb2OneCRL

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
