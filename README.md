# OneCRL-Tools

Some tools for supporting OneCRL.

Below is a description of each folder in this repository.

## bugzilla

**Status:** In use

**Description:** Defines API for interacting with Bugzilla.

**Usage:** See ccadb2OneCRL/main.go

**Used By:** ccadb2OneCRL

## ccadb2OneCRL

**Status:** In use

**Description:** Automates much of the process for taking reported/verified revocation data from the CCADB and adding it to OneCRL.

**Usage:** See the README in https://github.com/mozilla/OneCRL-Tools/tree/main/ccadb2OneCRL.

**Used By:** Security Engineers and Cloud Services

## containers

**Status:** In use

**Description:**  This is how ccadb2OneCRL gets deployed

**Usage:** See the README in https://github.com/mozilla/OneCRL-Tools/tree/main/containers

**Used By:** Security Engineers and Cloud Services

## entryMaker

**Status:** In use

**Description:** Given a certificate, output the corresponding data that can be added to OneCRL.

**Usage:** See the README in https://github.com/mozilla/OneCRL-Tools/tree/main/entryMaker

**Used By:** Security Engineers and Cloud Services

## kinto

**Status:** In use

**Description:** Defines API for interacting with Kinto.

**Usage:** See ccadb2OneCRL/main.go

**Used By:** ccadb2OneCRL

## tools/Salesforce2OneCRL-scheduler

**Status:** ???

**Description:** This is an AWS Lambda to perform scheduled OneCRL updates from the CCADB.

**Usage:** See README in https://github.com/mozilla/OneCRL-Tools/tree/main/tools/Salesforce2OneCRL-scheduler

**Used By:** ???

## transaction

**Status:** In Use

**Description:** Each step in the transaction holds a rollback procedure in the event of a downstream failure. For example, if putting staging into review fails, then Bugzilla ticket will be closed as `INVALID` with a stacktrace attached and all entries that were pushed to staging will be deleted.

**Usage:** See ccadb2OneCRL/main.go

**Used By:** ccadb2OneCRL
