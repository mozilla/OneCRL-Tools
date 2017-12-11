#/usr/bin/env bash

# This script is for deploying the certdataDiffCCADB tool to Heroku.
#
# Heroku DEMANDS that all applications be at the root of the project.
# Of course that is not the case here, so let's do something like
# use the subtree module to push to Heroku.
#
# You need to to be in the root of the repo in order to run this.
git subtree push --prefix cmd/certdataDiffCCADB heroku master
