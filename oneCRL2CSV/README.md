# onecrl2csv
A thing to make CSV files containing human readible entries

## Building
You need to have [Go](https://golang.org) intalled.

Check out OneCRL-Tools to your go root and do a:

```
go install github.com/mozmark/OneCRL-Tools/oneCRL2CSV
```

## Running
Open a terminal window.

From the directory containing the binary, do this:
```
$GOROOT/bin/onecrl2csv > filename.csv
```

### options
You can specify to location of the blocklist records like so:
```
./onecrl2csv -url=http://localhost:8080/v1/buckets/blocklists/collections/certificates/records
```
