# Create OneCRL Entry

Given a certificate, output the corresponding data that can be added to OneCRL.

## Build
```sh
go build
```

## Run
```sh
./entryMaker -cert [path to certificate] -bug [bug URL for the revocation]
```

Example:

```sh
./entryMaker -cert ~/certs/Information_Security_Certification_Authority_CA_pem.crt -bug 1864724
```
will produce an output like
```sh
{
        "issuerName": "MFgxCzAJBgNVBAYTAk5MMR4wHAYDVQQKDBVTdGF...",
    "serialNumber": "RR0ycJaMGZl88uTjuXcI7+J28xg=",
    "enabled": true,
    "details": {
      "who": "",
      "created": "2021-02-26T00:06:02Z",
      "bug": "1864724",
      "name": "",
      "why": ""
}
}
```
