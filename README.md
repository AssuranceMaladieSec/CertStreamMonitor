# CertStreamMonitor

Monitor certificates generated for specific domain strings and associated, and store data into sqlite3 database.

## Features
- monitor certstream-python feed (see [certstream-python](https://github.com/CaliDog/certstream-python))
- choose strings you want to monitor
- store data grabbed into a sqlite3 database

## Requirements
- Python 3
- certstream
- sqlite3

## Install
Install the requirements
~~~
$ pip3 install -r requirements.txt
~~~

## Configuration file
You can find a configuration file example placed into 'conf' directory
Configurable parameters are:
- SearchKeywords: Keywords to look for (with '|' (or) as separator
- DBFile: SQLite3 database file (the path and file will be created if don't exist)
- TABLEname: The name of the database table
- LogFile: The logging file (the path and file will be created if don't exist)

## Usage
~~~
$ python3 ./CertStreamMonitor.py -c conf/example.conf
Looking for these strings: paypal|apple|account|secure|login
Connection established to CertStream! Listening for events...
[30/11/17 11:24:37] paypal.com-myaccounts-countrys-pages-login.gq (SAN: ) (Issuer: /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3) (Fingerprint: 73:2A:BB:A7:3C:BB:4F:73:1E:CC:21:16:8A:E4:4D:2F:54:1E:45:2B) (StartTime: 30/11/17 - 09:05:48 UTC)
[30/11/17 11:24:49] account-disable-apple-id.tk (SAN: www.account-disable-apple-id.tk) (Issuer: /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3) (Fingerprint: 26:BC:5A:00:CA:52:3F:44:BB:89:FB:D5:37:A8:5B:F7:B8:07:B2:E7) (StartTime: 30/11/17 - 09:04:13 UTC)
[30/11/17 11:24:54] appleid.apple.com-security-verification.emailhosted.net (SAN: www.appleid.apple.com-security-verification.emailhosted.net) (Issuer: /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3) (Fingerprint: D8:3D:24:60:63:17:6D:25:9A:BC:A5:D2:B0:45:3B:70:72:C4:32:23) (StartTime: 30/11/17 - 09:05:12 UTC)
[30/11/17 11:25:00] paypal.com-myaccounts-countrys-pages-login.gq (SAN: ) (Issuer: /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3) (Fingerprint: 25:DF:12:DD:3B:A7:0A:1D:8A:0D:49:10:C1:1A:A1:96:BE:EE:A1:7C) (StartTime: 30/11/17 - 09:09:46 UTC)
[30/11/17 11:25:05] secure-account-disable-apple-id.cf (SAN: www.secure-account-disable-apple-id.cf) (Issuer: /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3) (Fingerprint: A5:E4:FE:20:AC:04:49:99:09:46:DD:B4:90:BD:7A:5F:A6:29:0A:F6) (StartTime: 30/11/17 - 09:06:51 UTC)
[30/11/17 11:25:06] secure-user-manage-account.cf (SAN: www.secure-user-manage-account.cf) (Issuer: /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3) (Fingerprint: 9D:3E:E0:4B:47:B5:95:E6:0A:7A:85:44:55:8D:F8:7D:89:32:43:BB) (StartTime: 30/11/17 - 09:07:05 UTC)
[30/11/17 11:25:13] www2.support.manage-account-idapple.com (SAN: ) (Issuer: /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3) (Fingerprint: 20:B8:BA:DC:6A:AE:67:2B:0D:6A:81:09:41:D6:40:7B:82:81:2E:5E) (StartTime: 30/11/17 - 09:08:21 UTC)
...
~~~
