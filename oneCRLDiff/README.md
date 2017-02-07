# oneCRLDiff
A thing to compare sets of OneCRL data

## Building
You need to have [Go](https://golang.org) intalled.

Check out OneCRL-Tools to your go root and do a:

```
go install github.com/mozmark/OneCRL-Tools/oneCRLDiff
```

## Running
Open a terminal window.

Do this:
```
$GOROOT/bin/oneCRLDiff <set1> <set2>
```

Where set1 and set2 are one of:
* An URL of a kinto OneCRL record set
* A revocations.txt file
* "stage" or "production" - special names for the stage and production
  Firefox settings services.

e.g:

```
$GOROOT/bin/oneCRLDiff path/to/some.profile/revocations.txt production
```
will give you the changes between a profile's current state and the
production data.
