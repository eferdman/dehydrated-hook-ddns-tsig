# dnspython hook for deyhdrated

This repository contains a python hook for the `dehydrated.sh` project, a Let's Encrypt/ACME client implemented as a shell script. This hook uses the dnspython API to perform dynamic DNS updates and queries to verify. The DNS challenge is outlined in the [ACME protocol](https://letsencrypt.github.io/acme-spec/#rfc.section.7.4). To successfully complete this challenge, the client creates a temporary TXT record containing a secret token for the given domain name, thereby proving ownership of the domain. 

## Required Python libraries
* [iscpy](https://pypi.python.org/pypi/iscpy) - an ISC config file parser
* [dnspython](http://www.dnspython.org/) - a DNS toolkit used for queries, zone transfers, and dynamic updates

## Installation
Download the files for installation

``` sh
  $ git clone https://github.com/lukas2511/dehydrated.git
  $ mkdir dehydrated/hooks
  $ git clone https://github.com/eferdman/dnspython-hook.git dehydrated/hooks/
```
## Configuration
The script reads the name of the key file from the environmental variable `DDNS_HOOK_KEY_FILE`

``` sh
  $ export DDNS_HOOK_KEY_FILE="path/to/key/file.key"
```
Replace the variable `name_server_ip` with the ip address of your master server.
Replace the variable `keyalgorithm` if using one other than hmac-md5

## Usage
See the [dehydrated script](https://github.com/lukas2511/dehydrated) for more options.

``` bash
$ cd dehydrated
$ ./dehydrated -c --challenge dns-01 --domain myblog.com --hook ./hooks/dnspython-hook.py
```

Or to test the script directly:

``` bash
$ python dnspython-hook.py deploy_challenge yourdomain.com - "Hello World"
$ python dnspython-hook.py clean_challenge yourdomain.com - "Hello World"
```

## Contribute
Please open an issue or submit a pull request.
