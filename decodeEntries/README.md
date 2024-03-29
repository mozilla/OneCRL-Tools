# decodeEntries

Converts OneCRL entry data from hexadecimal serials/hashes to non-encoded human-readable format.    
      
This tool is intended to be used by copy-pasting the contents of the [Line delimited issuer/serial pairs](https://bug1868611.bmoattachments.org/attachment.cgi?id=9367288) attachment to CCADB bugs that are created by the ccadb2OneCRL Tool.     
 
## Dependencies
To use this JavaScript, you will need to have Node and Forge installed.

## Run
Open index.html in your browser. 

## Input / Output

The input format is very specific, so don't add extra commas, quotes, etc.     
     
Example Input:     
issuer: MFAxJDAiBgNVBAsTG0dsb2JhbFNpZ24gRUNDIFJvb3QgQ0EgLSBSNDETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbg== serial: AhZo8c0KKo+EfYqtNA==     
issuer: MEcxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxITAfBgNVBAMTGFN3aXNzU2lnbiBTaWx2ZXIgQ0EgLSBHMg== serial: a8MYySrNF2PrQchvr0f3     
     
Example Output:     
issuer: /OU=GlobalSign ECC Root CA - R4/O=GlobalSign/CN=GlobalSign serial: 021668f1cd0a2a8f847d8aad34     
issuer: /C=CH/O=SwissSign AG/CN=SwissSign Silver CA - G2 serial: 6bc318c92acd1763eb41c86faf47f7     
     
     
