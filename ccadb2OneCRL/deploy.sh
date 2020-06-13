#!/usr/bin/env bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/. */

set -e

# We want source file:line information in our logging
# entries, however logrus cannot support this in the older
# version of the Go runtime built by 1.7 (what is available in apt).
#
# Besides, this is more portable between Debian/RHEL anyways.
curl -O -L https://golang.org/dl/go1.15.linux-amd64.tar.gz
echo '2d75848ac606061efe52a8068d0e647b35ce487a15bb52272c427df485193602  go1.15.linux-amd64.tar.gz' | sha256sum -c
tar zxf go1.15.linux-amd64.tar.gz

go/bin/go build -o ccadb2onecrl main.go
rm -rf go*
mkdir -p /opt/ccadb2onecrl
mv ccadb2onecrl /opt/ccadb2onecrl/
cp config.sh /opt/ccadb2onecrl/config.sh

cat <<EOF > /etc/cron.weekly/ccadb2onecrl
#!/usr/bin/env bash
set -e
/opt/ccadb2onecrl/ccadb2onecrl /opt/ccadb2onecrl/config.sh
EOF

chmod 755 /etc/cron.weekly/ccadb2onecrl
