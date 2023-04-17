# ccadb2OneCRL

### Execution Flow

1. Authentication for Kinto Staging and Kinto Production is attempted. If authentication fails for either-or-both, exit.
2. If Kinto Staging is in the `in-review` state then a comment is posted to Bugzilla for the issues that are still open. Exit.
3. Compute all entries that are within the CCADB that are not within either Kinto Staging nor Kinto Production. If no such entries are found, exit.
4. The following transaction is built and executed

```go
transaction.Start().
    // Push the candidate changes to staging. 
    Then(u.PushToStaging()).
    // Open a Bugzilla ticket with information about the above changes.
    Then(u.OpenBug()).
    // Update the records from PushToStaging to hold the Bugzilla IF just generated.
    Then(u.UpdateRecordsWithBugID()).
    // Put Kinto Staging into review.
    Then(u.PutStagingIntoReview()).
    // Push the candidate changes to production. Accepting these changes remains a manual step.
    Then(u.PushToProduction()).
```

Each step in the transaction holds a rollback procedure in the event of a downstream failure. For example, if putting staging into review fails, then Bugzilla ticket will be closed as `INVALID` with a stacktrace attached and all entries that were pushed to staging will be deleted.

### Sample Output

The following is a sample output to Bugzilla dev of a successful run:

https://bugzilla-dev.allizom.org/show_bug.cgi?id=1629310

The following is a sample output to Bugzilla dev when a mocked failure occurred while pushing to staging:

https://bugzilla-dev.allizom.org/show_bug.cgi?id=1629313

### Deployment
A convenience script, `deploy.sh`, has been provided for deployment that is portable to _most_ Linux systems. The script has a single dependency on the local `cron` system being configured to read from `/etc/cron.weekly/`.

### Testing
If you have Docker installed, then `go test .` will fire up a local Kinto instance that is used to simulate Kinto Staging/Production and uses Bugzilla's open development instance.

### Configuration

This tool takes in exactly one optional argument - a path to a configuration file.

```bash
./ccadb2OneCRL /opt/configDir/prod.env
```

If no path is provided, then this tool defaults to looking for a `config.env` file within the same directory as the executable itself (which is NOT necessarily the callers present working directory).

For example:

```bash
# /
# ├── opt
#     ├── ccadb2onecrl
#     │   ├── ccadb2onecrl
#     │   └── config.env

$ /opt/ccadb2onecrl/ccadb2onecrl
```

...will run using the configuration found at `/opt/ccadb2onecrl/config.env`.

The following is a sample configuration file. Note that this sample still requires some fields to be filled it, notably the `TOKEN/API KEY` fields for Kinto staging/production as well as for Bugzilla.

```.env
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Base URL for Kinto production [default: "https://firefox.settings.services.mozilla.com/v1"]
#ONECRL_PRODUCTION="https://firefox.settings.services.mozilla.com/v1"

# User account for Kinto production. Requires OneCRLProductionPassword to be set. Mutually exclusive with OneCRLProductionToken.
#ONECRL_PRODUCTION_USER=

# User password for Kinto production. Requires OneCRLProductionUser to be set. Mutually exclusive with OneCRLProductionToken.
#ONECRL_PRODUCTION_PASSWORD=

# Auth token for Kinto production. Mutually exclusive with OneCRLProductionUser and OneCRLProductionPassword.
ONECRL_PRODUCTION_TOKEN=

# Target production bucket [default: "security-state"]
# Default is likely what you want as this is mostly configurable for testing purposes.
#ONECRL_PRODUCTION_BUCKET="security-state"

# Target production collection [default: "onecrl"]
# Default is likely what you want as this is mostly configurable for testing purposes.
#ONECRL_PRODUCTION_COLLECTION="onecrl"

# Base URL for Kinto production [default: "https://firefox.settings.services.allizom.org/v1"]
#ONECRL_STAGING="https://firefox.settings.services.allizom.org/v1"

# User account for Kinto staging. Requires OneCRLStagingPassword to be set. Mutually exclusive with OneCRLStagingToken.
#ONECRL_STAGING_USER=

# User password for Kinto staging. Requires OneCRLStagingUser to be set. Mutually exclusive with OneCRLStagingToken.
#ONECRL_STAGING_PASSWORD=

# Auth token for Kinto staging. Mutually exclusive with OneCRLStagingUser and OneCRLStagingPassword.
ONECRL_STAGING_TOKEN=

# Target staging bucket [default: "security-state"].
# Default is likely what you want as this is mostly configurable for testing purposes.
# ONECRL_STAGING_BUCKET="security-state"

# Target staging collection [default: "onecrl"]
# Default is likely what you want as this is mostly configurable for testing purposes.
# ONECRL_STAGING_COLLECTION="onecrl"

# Base URL for Bugzilla [default: "https://bugzilla.mozilla.org"]
# BUGZILLA="https://bugzilla.mozilla.org"

# Mandatory API key for posting to Bugzilla. This key MUST have write permissions.
BUGZILLA_API_KEY=

# Optional. A comma separated list of of email accounts to put on CC for new bugs. If these accounts are not
# registered with the configured Bugzilla, then a runtime error will occur when creating new bugs.
# BUGZILLA_CC_ACCOUNTS="alice@secrets.org, eve@legit.ru"

# Target logging level for this tool.
#   Available: panic, fatal, error, warn, warning info, debug, trace
#   Default: info
#LOG_LEVEL="info"

# Target directory for logs [default: stdout/stderr]
# Each run of the tool will be logged to the timestamp of when it was ran.
LOG_DIR=/opt/ccadb2onecrl/logs

```
