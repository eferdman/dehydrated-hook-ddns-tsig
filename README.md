# dnspython hook for dehydrated

This repository contains a python hook for the `dehydrated.sh` project, a Let's Encrypt/ACME client implemented as a shell script. This hook uses the dnspython API to perform dynamic DNS updates and queries to verify. The DNS challenge is outlined in the [ACME protocol](https://letsencrypt.github.io/acme-spec/#rfc.section.7.4). To successfully complete this challenge, the client creates a temporary TXT record containing a secret token for the given domain name, thereby proving ownership of the domain. 

## Required Python libraries
* [dnspython](http://www.dnspython.org/) - a DNS toolkit used for queries, zone transfers, and dynamic updates
* (optional) [iscpy](https://pypi.python.org/pypi/iscpy) - an ISC config file parser (only needed when reading keys from an extra file)

## Installation
Download the files for installation

``` sh
  $ git clone https://github.com/lukas2511/dehydrated.git
  $ mkdir -p dehydrated/hooks/dnspython
  $ git clone https://github.com/eferdman/dnspython-hook.git dehydrated/hooks/dnspython
```

## Configuration
The script reads a configuration file as specified via the cmdline (using the `--config` flag),
falling back to these default config files:
- `$(pwd)/dnspython-hook.conf`
- `/etc/dehydrate/dnspython-hook.conf`
- `/usr/local/etc/dehydrate/dnspython-hook.conf`

The configuration file uses a simple `INI`-style syntax,
where you can set the parameters for each domain separately (by creating a section named after the domain),
with default values in the `[DEFAULT]` section.

The following parameters can be set:
- `name_server_ip` the DNS server IP that will serve the ACME challenge (**required**)
- `TTL` time-to-live value for the challenge (default: *300*)
- `wait` time - in seconds - to wait before verifying that the challenge is really deployed/deleted; use negative values to skip the check (default: *5*)
- `verbosity` verbosity of the script: use negative values to suppress more messages (default: *0*)
- `key_name` name of the key to use for authentication with the DNS server (**required**, see [below](#using-an-extra-key-file))
- `key_secret` the base64-encoded key secret (**required**, see [below](#using-an-extra-key-file))
- `key_algorithm` the hashing algorithm of the key (default: *hmac-md5*)

A complete example can be found in the `dnspython-hook.conf` file.

### Using an extra key file
If you do not want to specify key name and key secret in the config file,
you can provide that information in an extra file.

The script reads the name of this key file from the environmental variable `DDNS_HOOK_KEY_FILE`

``` sh
  $ export DDNS_HOOK_KEY_FILE="path/to/key/file.key"
```

The file must be formatted in an [rndc/bind](https://ftp.isc.org/isc/bind9/cur/9.9/doc/arm/man.rndc.conf.html) compatible way.

Only when using *this* method for acquiring the key,
you must have [iscpy](https://pypi.python.org/pypi/iscpy) installed.


## Usage
See the [dehydrated script](https://github.com/lukas2511/dehydrated) for more options.

``` bash
$ cd dehydrated
$ ./dehydrated -c --challenge dns-01 --domain myblog.com --hook ./hooks/dnspython/dnspython-hook.py
```

Or to test the script directly:

``` bash
$ python dnspython-hook.py deploy_challenge yourdomain.com - "Hello World"
$ python dnspython-hook.py clean_challenge yourdomain.com - "Hello World"
```

## Contribute
Please open an issue or submit a pull request.
