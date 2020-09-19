#!/bin/bash -xe

VER=staging

cd $(dirname ${0})
printf '{"commit":"%s","version":"%s","source":"https://github.com/%s/%s","build":"%s"}\n' \
                "$(git rev-parse HEAD)" \
                "$(git describe --tags)" \
                "$(id -u -n)" \
                "OneCRL-Tools" \
                "localhost" > ../version.json
docker build -t ccadb2onecrl:${VER} .. -f Dockerfile
rm ../version.json
