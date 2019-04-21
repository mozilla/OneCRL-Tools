# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FROM golang:latest AS buildStage

WORKDIR /opt
COPY . .
# Enabling CGO produces a binary that is not
# 100% statically linked. Alpine doesn't have
# everything we need to run, and we don't
# really want to go through DLL hell, so we need
# to make sure to statically link everything
# that we need by disabling CGO.
ENV CGO_ENABLED=0
RUN go build -o certdataDiffCCADB main.go

FROM alpine:latest
RUN apk --update add ca-certificates
COPY --from=buildStage /opt/ /opt/

CMD ["/opt/certdataDiffCCADB", "--serve"]
