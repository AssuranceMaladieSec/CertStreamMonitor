# CertStreamMonitor

Monitor certificates generated for specific domain strings and associated, store data into sqlite3 database, alert you when sites come online.

CertStreamMonitor architecture relies on 2 scripts :

- `certstreammonitor.py`
  - this script runs as a daemon.
  - reading the certstream feed, it selects hostnames covered by certificates that match your criteria (SearchKeyWords parameter in conf).
  - it writes these hostnames along with its certificate relevant informations to the database.
- `scanhost.py`
  - this script can be run as often you want.
  - it checks if site corresponding to the hostanme stored in DB is UP ot not.
  - it collects informations about the sites that are up to DB and to a JSON file.

## Features
- **Monitoring:**
  - monitor wss://certstream.calidog.io CT logs aggregator server with certstream-python (see [certstream-python](https://github.com/CaliDog/certstream-python)), but you can choose, and operate, your own server (see [certstream-server](https://github.com/CaliDog/certstream-server/)).
  - choose strings you want to monitor in Subject Alt Names or Domain fields of certificates
- **Storing:**
  - store hostnames found along with its certificate relevant data into a sqlite3 database
- **Alerting:**
  - for each hostname not already flagged as up : check if corresponding site is up or not
  - if it is, it :
    - collects informations (IP address, AS informations, HTTP code, web page title, abuse email)
    - write them to a JSON file in the `/alerts` directory (default value) to push forward investigation.
    - flags the hostname in the DB as up

## Requirements
- Python 3
- certstream
- sqlite3
- websocket-client

## Install
Install the requirements
~~~
$ pip3 install -r requirements.txt
~~~

## Configuration file
You can find a configuration file example placed into 'conf' directory.
Configurable parameters are:
- `SearchKeywords`: Keywords to look for (with '|' (or) as separator)
- `DetectionThreshold`: set the minimum number of detected SearchKeywords in a hostname before writing it to DB. Under this value but above zero, detected hostnames are only written to logfile. Default value: 2.
- `DBFile`: SQLite3 database file (the path and file will be created if don't exist)
- `TABLEname`: The name of the database table
- `LogFile`: The logging file (the path and file will be created if don't exist)
- `Proxy`: allows to give a SOCKS or HTTP proxy to process your scanhost.py's requests (as Tor)
- `UAfile`: you can provide a User-Agent file to masquerade this value of requests (random change for each request)
- `Alerts_dir`: you can specify where JSON alert files are written
   You can use the following strings to add time/date hashed based subdirectories:
   %%m -> month, %%d -> day, %%Y -> year, %%H -> hour, %%M -> minute.
   Example: Alerts_dir = ./alerts/%%Y/%%m/%%d
- `ACTServer`: you can specify the CT logs aggregator server of your choice. By default, it is the server run by Calidog Security.
- `Proxy_*` parameters : allow you to specify HTTP proxy informations (server, port[, user, password]) for CertStreamMonitor.py script to connect to the CT logs aggregator server.

## Usage

### CertStreamMonitor.py

~~~
$ python3 ./CertStreamMonitor.py -c conf/example.conf
Looking for these strings: paypal|apple|account|secure|login, detection threshold: 2
Connection established to CertStream! Listening for events...
[2018-03-12T11:40:15] cpanel.my-appleid-apple.net (SAN: mail.my-appleid-apple.net,my-appleid-apple.net,webdisk.my-appleid-apple.net,webmail.my-appleid-apple.net,www.my-appleid-apple.net) (Issuer: /C=US/CN=Let's Encrypt Authority X3/O=Let's Encrypt) (Fingerprint: 45:11:51:2D:24:D3:04:6E:DF:49:46:6D:64:56:67:4B:0A:48:8D:93) (StartTime: 2018-03-12T10:39:40)
[2018-03-12T11:41:19] cpanel.verification-account-apple-now.com (SAN: mail.verification-account-apple-now.com,verification-account-apple-now.com,webdisk.verification-account-apple-now.com,webmail.verification-account-apple-now.com,www.verification-account-apple-now.com) (Issuer: /C=US/CN=Let's Encrypt Authority X3/O=Let's Encrypt) (Fingerprint: 2D:90:F9:F7:83:F6:48:26:EF:C9:72:50:4B:06:FA:36:53:94:3C:8B) (StartTime: 2018-03-12T10:40:49)
[2018-03-12T11:41:36] login-apple.sytes.net (SAN: ) (Issuer: /C=US/CN=Let's Encrypt Authority X3/O=Let's Encrypt) (Fingerprint: C7:78:2F:08:1E:CC:83:6C:06:EF:77:14:D2:1A:4E:06:A8:B3:F9:77) (StartTime: 2018-03-12T10:41:08)
[2018-03-12T11:42:26] cpanel.restore-account-apple.com (SAN: mail.restore-account-apple.com,restore-account-apple.com,webdisk.restore-account-apple.com,webmail.restore-account-apple.com,www.restore-account-apple.com) (Issuer: /C=US/CN=Let's Encrypt Authority X3/O=Let's Encrypt) (Fingerprint: F3:CA:B1:C6:DE:4F:05:16:FD:06:F3:FF:29:8A:D3:1F:10:9D:50:1A) (StartTime: 2018-03-12T10:41:59)
[2018-03-12T11:49:37] securelogin.here.att.thysseankrupp.com (SAN: ) (Issuer: /C=US/CN=Let's Encrypt Authority X3/O=Let's Encrypt) (Fingerprint: 8F:9B:98:8D:5D:9B:03:0B:4F:62:56:40:C1:DE:9A:A4:FB:2D:A3:3E) (StartTime: 2018-03-12T09:22:41)
...
~~~

### scanhost.py

~~~
$ python3 scanhost.py --help

    -h --help		Print this help
    -c --config		Configuration file to use
    -f --fqdn-dirs  Store JSON files in sub-directories based on the hostname
~~~

~~~
$ python3 ./scanhost.py -c conf/test.conf
Test all domains in DB for Internet Presence:
*********************************************
14:30:12 - ERROR -   https://socialparadiseweb.cf.socialparadise.cf - Connection error
14:32:18 - ERROR -   https://rapportannuel-assurancemaladie.paris - Connection error
14:32:23 - SUCCESS - HTTP 200 - socialmediaforsocialaction.com
Creating ./alerts/socialmediaforsocialaction.com.json : {'hostname': 'socialmediaforsocialaction.com', 'http_code': 200, 'cert_serial_number': '89:6C:03:F6:82:57:03:2A:A8:D0:E1:2F:E8:56:0E:32:83:E5:EC:29', 'webpage_title': 'Social Media for Social Action', 'ip_addr': '198.49.23.145', 'asn': '53831', 'asn_cidr': '198.49.23.0/24', 'asn_country_code': 'US', 'asn_description': 'SQUARESPACE - Squarespace, Inc., US', 'asn_abuse_email': 'abuse-network@squarespace.com'}
14:32:25 - ERROR -   https://social.socialbride.co.za - Connection error
14:32:34 - SUCCESS - HTTP 503 - assurances-sociales.com
Creating ./alerts/assurances-sociales.com.json : {'hostname': 'assurances-sociales.com', 'http_code': 503, 'cert_serial_number': '1A:0D:45:D9:05:15:DC:17:6C:9F:9E:47:A5:62:03:D9:25:02:F9:3C', 'webpage_title': 'Accueil', 'ip_addr': '164.132.235.17', 'asn': '16276', 'asn_cidr': '164.132.0.0/16', 'asn_country_code': 'FR', 'asn_description': 'OVH, FR', 'asn_abuse_email': 'lir@ovh.net'}
~~~

## Authors
- Thomas Damonneville ([thomas.damonneville@assurance-maladie.fr](mailto:thomas.damonneville@assurance-maladie.fr))
- Christophe Brocas ([christophe.brocas@assurance-maladie.fr](mailto:christophe.brocas@assurance-maladie.fr))

## Presentations
- [FRENCH] Brocas, Damonneville. ["Certificate Transparency ou comment un nouveau standard peut aider votre veille sur certaines menaces"](https://www.sstic.org/2018/presentation/certificate_transparency_ou_comment_un_nouveau_standard_peut_aider_votre_analyse_des_menaces/), SSTIC 2018.

## License
GNU GENERAL PUBLIC LICENSE (GPL) Version 3
