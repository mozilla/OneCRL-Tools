#!/bin/bash -xe

VER=staging

cd $(dirname ${0})
docker build -t ccadb2onecrl:${VER} .. -f Dockerfile
