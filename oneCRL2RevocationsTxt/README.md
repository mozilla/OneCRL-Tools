# oneCRL2RevocationsTxt
A thing to make revocations.txt files for testing in Firefox profiles.

## Building
You need to have [Go](https://golang.org) intalled.

Check out OneCRL-Tools to your go root and do a:

```
go install github.com/mozmark/OneCRL-Tools/oneCRL2RevocationsTxt
```

## Running
Open a terminal window.

Do this:
```
$GOROOT/bin/onecrl2RevocationsTxt > revocations.txt
```

### Options

You can specify that you want to get data from the staging instance of the
firefox settings service like this:

```
$GOROOT/bin/onecrl2RevocationsTxt --env stage > revocations.txt
```
