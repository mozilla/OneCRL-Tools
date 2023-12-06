"use strict";

function base64ToHex(base64) {
  let byteString = atob(base64);
  let output = "";
  for (let i = 0; i < byteString.length; i++) {
    output += (output ? "" : "") + byteString
                                    .charCodeAt(i)
                                    .toString(16)
                                    .padStart(2, "0");
  }
  return output;
}

function formatRDNS(rdns) {
  let output = "";
  rdns.forEach((rdn) => {
    output += `/${rdn.shortName}=${forge.util.decodeUtf8(rdn.value)}`;
  });
  return output;
}

function parseBase64DN(base64) {
  let byteString = atob(base64);
  let asn1 = forge.asn1.fromDer(byteString);
  let rdns = forge.pki.RDNAttributesAsArray(asn1, null);
  return rdns;
}

function decodeLine(line) {
  let parts = line.split(" ");
  let issuer = formatRDNS(parseBase64DN(parts[1]));
  let serial = base64ToHex(parts[3]);
  return { issuer, serial }; 
}

function decodeFromInput() {
  let input = document.getElementById("input").value;
  let output = document.getElementById("output");
  while (output.childNodes.length > 0) {
    output.removeChild(output.childNodes[0]);
  }
  let lines = input.split("\n");
  lines.forEach((line) => {
    if (line.length > 0) {
      let text;
      try {
        let decoded = decodeLine(line);
        text = `issuer: ${decoded.issuer} serial: ${decoded.serial}`;
      } catch (e) {
        text = `Couldn't decode entry: ${line}`;
      }
      let textNode = document.createTextNode(text);
      output.appendChild(textNode);
      let br = document.createElement("br");
      output.appendChild(br);
    }
  });
}
