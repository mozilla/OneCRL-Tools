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
