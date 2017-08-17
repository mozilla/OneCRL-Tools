#!/bin/bash

echo -n "Testing oneCRL2RevocationsTxt installation ..."
go install github.com/mozilla/OneCRL-Tools/oneCRL2RevocationsTxt &>/tmp/oneCRL2RevocationsTxt-install.out
if [ $? -ne 0 ]
then
	echo " fail"
	echo "FAIL: go install github.com/mozilla/OneCRL-Tools/oneCRL2RevocationsTxt"
	cat /tmp/oneCRL2RevocationsTxt-install.out
	exit 5
fi
echo " ok"


echo -n "Testing oneCRL2RevocationsTxt invocation ..."
"${GOPATH}/bin/oneCRL2RevocationsTxt" >/tmp/oneCRL2RevocationsTxt.out
if [ $? -ne 0 ]
then
	echo " fail"
	echo "FAIL: unable to run oneCRL2RevocationsTxt"
	exit 5
fi
echo " ok"


echo -n "Checking oneCRL2RevocationsTxt output ..."
num_lines=$(wc -l /tmp/oneCRL2RevocationsTxt.out | awk '{print $1}')
num_chars=$(wc -c /tmp/oneCRL2RevocationsTxt.out | awk '{print $1}')
if [ ${num_lines} -lt 50 ]
then
	echo " fail"
	echo "FAIL: oneCRL2RevocationsTxt output has suspisciously few lines (<50)"
	exit 5
fi
if [ ${num_chars} -lt 2400 ]
then
	echo " fail"
	echo "FAIL: oneCRL2RevocationsTxt output has suspisciously few characters (<2400)"
	exit 5
fi
echo " ok"
