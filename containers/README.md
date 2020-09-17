# This folder defines a container for the CCADB to OneCRL tool.

## Constructing the container
```sh
./build-local.sh
```

## Running the container
```sh
docker run --rm --init -t ccadb2onecrl:staging
```

this will exit with invalid permissions. A more complete run might be:

```sh
docker run --rm --init \
  --env "ONECRL_PRODUCTION_TOKEN=a" \
  --env "ONECRL_STAGING_TOKEN=b" \
  --env "BUGZILLA_API_KEY=c" \
  --env "BUGZILLA_CC_ACCOUNTS=example.user@mozilla.com, other.user@mozilla.com" \
  -t ccadb2onecrl:staging
```

Alternatively, you can specify all environment variables using a dot-env file, such as:

```sh
mkdir /tmp/ccadb2onecrl
cat >/tmp/ccadb2onecrl/config.env<<EOF
ONECRL_STAGING_USER=a
ONECRL_STAGING_PASSWORD=b
ONECRL_PRODUCTION_USER=c
ONECRL_PRODUCTION_PASSWORD=d
BUGZILLA_API_KEY=c
BUGZILLA_CC_ACCOUNTS="example.user@mozilla.com, other.user@mozilla.com"
EOF
docker run --rm --init \
  --volume=/tmp/ccadb2onecrl:/config:ro \
  -t ccadb2onecrl:staging
```