FROM golang:1.13-buster as builder
RUN mkdir /build
WORKDIR /build
RUN mkdir bin gopath
ENV GOPATH /build/gopath
ADD . /build/gopath/src/github.com/mozilla/OneCRL-Tools/

RUN go get github.com/mozilla/OneCRL-Tools/ccadb2OneCRL
RUN go build -o bin/ccadb2OneCRL github.com/mozilla/OneCRL-Tools/ccadb2OneCRL

FROM python:3.8-buster
RUN apt update && apt install -y ca-certificates && \
    apt -y upgrade && apt-get autoremove --purge -y && \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/*

RUN adduser --system --uid 10001 --group --home /app app

COPY --from=builder /build/bin /app/
# Don't have any default configuration; leave it to the Docker runner
RUN touch /app/config.env

USER app
WORKDIR /app

CMD [ "/app/ccadb2OneCRL" ]