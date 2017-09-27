# Salesforce2OneCRL-scheduler

This is an AWS Lambda to perform scheduled OneCRL updates from the CCADB.

## Building the function package

Create a .config.yml file in the Salesforce2OneCRL-scheduler directory. The supplied config-sample.yml is a good starting point.

Set your ```GOPATH``` and run ```make``` from the Salesforce2OneCRL-scheduler directory.
This will generate a file called ccadb_scheduler.zip

## Environment

You will need to provide credentials for bugzilla and kinto. You can do this by setting ```bzapikey``` to a valid bugzilla API key,
and ```kintouser``` and ```kintopass``` to a valid kinto username and password.
