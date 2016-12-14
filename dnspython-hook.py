#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# dnspython-hook - dns-01 Challenge Hook Script for dehydrated.sh
#
# This script uses the dnspython API to create and delete TXT records
# in order to prove ownership of a domain.
#
# Copyright (C) 2016 Elizabeth Ferdman https://eferdman.github.io
# Copyright (C) 2016 IOhannes m zmölnig <zmoelnig@iem.at>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
############################################################################

# callbacks
# deploy_challenge <DOMAIN> <TOKEN_FILENAME> <TOKEN_VALUE>
# clean_challenge <DOMAIN> <FILENAME> <TOKEN_VALUE>
# deploy_cert <DOMAIN> <KEYFILE> <CERTFILE> <FULLCHAIN> <CHAINFILE> <TIMESTAMP>
# unchanged_cert DOMAIN> <KEYFILE> <CERTFILE> <FULLCHAINFILE> <CHAINFILE>


import os
import sys
import time
import logging
import dns.resolver
import dns.tsig
import dns.tsigkeyring
import dns.update
import dns.query
from dns.exception import DNSException


# the default configuration
defaults = {
    "configfiles": [
        "/etc/dehydrated/dnspython-hook.conf",
        "/usr/local/etc/dehydrated/dnspython-hook.conf",
        "dnspython-hook.conf", ],
    "name_server_ip": '10.0.0.1',
    "ttl": 300,
    "sleep": 5,
    "loglevel": logging.WARN,
    }
# valid key algorithms (but bind9 only supports hmac-md5)
key_algorithms = {
    "": dns.tsig.HMAC_MD5,
    "hmac-md5": dns.tsig.HMAC_MD5,
    "hmac-sha1": dns.tsig.HMAC_SHA1,
    "hmac-sha224": dns.tsig.HMAC_SHA224,
    "hmac-sha256": dns.tsig.HMAC_SHA256,
    "hmac-sha384": dns.tsig.HMAC_SHA384,
    "hmac-sha512": dns.tsig.HMAC_SHA512,
    }

# Configure some basic logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())


def set_verbosity(verbosity):
    oldlevel = logger.getEffectiveLevel()
    level = int(defaults["loglevel"] - (10 * verbosity))
    if level <= 0:
        level = 1
    logger.setLevel(level)


set_verbosity(0)


def post_hook(name, cfg, args):
    key = "post_%s" % (name,)
    if key in cfg:
        import subprocess
        callargs = [cfg[key], name]
        for a in args:
            callargs += [cfg[a]]
        logger.info(' + Calling post %s hook: %s' % (name, ' '.join(callargs)))
        subprocess.call(callargs)


def get_key_algo(name='hmac-md5'):
    try:
        return key_algorithms[name]
    except KeyError:
        logger.debug("", exc_info=True)
        logger.fatal("""Invalid key-algorithm '%s'
Only the following algorithms are allowed: %s"""
                     % (name, " ".join(key_algorithms.keys())))
        sys.exit(1)


def get_isc_key():
    try:
        import iscpy
    except ImportError:
        logger.debug("", exc_info=True)
        logger.fatal("""The 'iscpy' module is required to read keys from isc-config file.
Alternatively set key_name/key_secret in the configuration file""")
        sys.exit(1)
    key_file = os.environ.get('DDNS_HOOK_KEY_FILE')

    # Open the key file for reading
    try:
        f = open(key_file, 'rU')
    except IOError:
        logger.debug("", exc_info=True)
        logger.fatal("""Unable to read isc-config file!
Did you set the DDNS_HOOK_KEY_FILE env?
Alternatively set key_name/key_secret in the configuration file""")
        sys.exit(1)

    # Parse the key file
    parsed_key_file = iscpy.ParseISCString(f.read())

    # Grab the keyname, cut out the substring "key "
    # and remove the extra quotes
    key_name = parsed_key_file.keys()[0][4:].strip('\"')

    # Grab the secret key
    secret = parsed_key_file.values()[0]['secret'].strip('\"')
    f.close()

    return (key_name, secret)


# Create a TXT record through the dnspython API
# Example code at
#  https://github.com/rthalley/dnspython/blob/master/examples/ddns.py
def create_txt_record(
        domain_name, token,
        name_server_ip,
        keyring, keyalgorithm=dns.tsig.HMAC_MD5,
        ttl=300,
        sleep=5,
        timeout=10
        ):
    logger.info(' + Creating TXT record "%s" for the domain _acme-challenge.%s'
                % (token, domain_name))

    domain_list = ['_acme-challenge'] + domain_name.split('.')
    for i in range(1, len(domain_list)):
        update = dns.update.Update(
            '.'.join(domain_list[i:]),
            keyring=keyring,
            keyalgorithm=keyalgorithm)
        update.add('.'.join(domain_list[:i]), ttl, 'TXT', token)
        logger.debug(str(update))
        try:
            response = dns.query.udp(update, name_server_ip, timeout=timeout)
            rcode = response.rcode()
            logger.debug(" + Adding TXT record %s -> %s returned %s" % (
                '.'.join(domain_list[:i]),
                '.'.join(domain_list[i:]),
                dns.rcode.to_text(rcode)))
            if rcode is dns.rcode.NOERROR:
                break
        except DNSException as err:
            logger.debug("", exc_info=True)
            logger.error(err)

    # Wait for DNS record to propagate
    if (sleep < 0):
        return

    time.sleep(sleep)

    # Check if the TXT record was inserted
    try:
        answers = dns.resolver.query('_acme-challenge.' + domain_name, 'TXT')
    except DNSException as err:
        logger.debug("", exc_info=True)
        logger.fatal("Unable to check if TXT record was successfully inserted")
        sys.exit(1)
    else:
        txt_records = [txt_record.strings[0] for txt_record in answers]
        if token in txt_records:
            logger.info(" + TXT record successfully added!")
        else:
            logger.fatal(" + TXT record not added.")
            sys.exit(1)


# Delete the TXT record using the dnspython API
def delete_txt_record(
        domain_name, token,
        name_server_ip,
        keyring, keyalgorithm=dns.tsig.HMAC_MD5,
        ttl=300,
        sleep=5,
        timeout=10
        ):
    logger.info(' + Deleting TXT record "%s" for the domain _acme-challenge.%s'
                % (token, domain_name))

    # Retrieve the specific TXT record
    txt_record = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        token)

    domain_list = ['_acme-challenge'] + domain_name.split('.')
    for i in range(1, len(domain_list)):
        # Attempt to delete the TXT record
        update = dns.update.Update(
            '.'.join(domain_list[i:]),
            keyring=keyring,
            keyalgorithm=keyalgorithm)
        update.delete('.'.join(domain_list[:i]), txt_record)
        logger.debug(str(update))
        try:
            response = dns.query.udp(update, name_server_ip, timeout=timeout)
            rcode = response.rcode()
            logger.debug(" + Removing TXT record %s -> %s returned %s" % (
                '.'.join(domain_list[:i]),
                '.'.join(domain_list[i:]),
                dns.rcode.to_text(rcode)))
            if rcode is dns.rcode.NOERROR:
                break
        except DNSException as err:
            logger.debug("", exc_info=True)
            logger.error("Error deleting TXT record")

    # Wait for DNS record to propagate
    if (sleep < 0):
        return
    time.sleep(sleep)

    # Check if the TXT record was successfully removed
    try:
        answers = dns.resolver.query('_acme-challenge.' + domain_name, 'TXT')
    except DNSException as err:
        logger.debug("", exc_info=True)
        logger.fatal("Unable to check if TXT record was successfully removed")
        sys.exit(1)
    else:
        txt_records = [txt_record.strings[0] for txt_record in answers]
        if token in txt_records:
            logger.info(" + TXT record not successfully deleted.")
            sys.exit(1)
        else:
            logger.info(" + TXT record successfully deleted.")


# callback to show the challenge via DNS
def deploy_challenge(cfg):
    ensure_config_dns(cfg)
    create_txt_record(
        cfg["args"]["domain"], cfg["args"]["token"],
        cfg["config"]["name_server_ip"],
        cfg["config"]["keyring"], cfg["config"]["keyalgorithm"],
        ttl=cfg["config"]["ttl"],
        sleep=cfg["config"]["wait"],
        )
    post_hook('deploy_challenge', cfg, ['domain', 'tokenfile', 'token'])


# callback to clean the challenge from DNS
def clean_challenge(cfg):
    ensure_config_dns(cfg)
    delete_txt_record(
        cfg["args"]["domain"], cfg["args"]["token"],
        cfg["config"]["name_server_ip"],
        cfg["config"]["keyring"], cfg["config"]["keyalgorithm"],
        ttl=cfg["config"]["ttl"],
        sleep=cfg["config"]["wait"],
        )
    post_hook('clean_challenge', cfg, ['domain', 'tokenfile', 'token'])


# callback to deploy the obtained certificate
# (currently unimplemented)
def deploy_cert(cfg):
    post_hook(
        'deploy_cert', cfg,
        ['domain',
         'keyfile', 'certfile',
         'fullchainfile', 'chainfile', 'timestamp'])


# callback when the certificate has not changed
# (currently unimplemented)
def unchanged_cert(cfg):
    post_hook(
        'unchanged_cert', cfg,
        ['domain', 'keyfile', 'certfile', 'fullchainfile', 'chainfile'])


def ensure_config_dns(cfg):
    """make sure that the configuration can be used to update the DNS
(e.g. read rndc-key if missing; fix some values if present)
"""
    # (str)key_name
    # (str)key_secret
    # (str)name_server_ip
    # (int)ttl
    # (float)wait

    try:
        key_name = cfg["config"]["key_name"]
        key_secret = cfg["config"]["key_secret"]
    except KeyError:
        (key_name, key_secret) = get_isc_key()

    keyringd = {key_name: key_secret}
    keyring = dns.tsigkeyring.from_text(keyringd)
    cfg["config"]["keyring"] = keyring

    try:
        algo = cfg["config"]["key_algorithm"]
    except KeyError:
        algo = ""
    algo = get_key_algo(algo)
    cfg["config"]["keyalgorithm"] = algo

    if "ttl" in cfg["config"]:
        cfg["config"]["ttl"] = int(float(cfg["config"]["ttl"]))
    else:
        cfg["config"]["ttl"] = defaults["ttl"]

    if "wait" in cfg["config"]:
        cfg["config"]["wait"] = float(cfg["config"]["wait"])
    else:
        cfg["config"]["wait"] = defaults["sleep"]

    if "name_server_ip" not in cfg["config"]:
        cfg["config"]["name_server_ip"] = defaults["name_server_ip"]

    return cfg


def read_config(args):
    try:
        import configparser
    except ImportError:
        import ConfigParser as configparser

    cfgfiles = defaults["configfiles"]
    if args.config:
        cfgfiles = args.config

    config = configparser.ConfigParser()
    config.read(cfgfiles)

    domain = args.domain[0]
    if domain in config.sections():
        config = config[domain]
    else:
        config = config.defaults()

    if "verbosity" in config and not args.verbose:
        verbosity = float(config["verbosity"])
        set_verbosity(verbosity)

    result = dict()

    d = dict()
    for c in config:
        d[c] = config[c]
    result["config"] = d

    d = dict()
    args = vars(args)
    for c in args:
        if type(args[c]) is list:
            d[c] = args[c][0]
    result["args"] = d

    return result


def parse_args():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config",
        help="Read options from configuration files [%s]"
             % (", ".join(defaults["configfiles"])),
        action='append',
        metavar="FILE")
    parser.add_argument(
        "-v", "--verbose",
        help="Raise verbosity",
        action='count', default=0)
    parser.add_argument(
        "-q", "--quiet",
        help="Lower verbosity",
        action='count', default=0)

    subparsers = parser.add_subparsers(help='sub-command help')

    parser_deploychallenge = subparsers.add_parser(
        'deploy_challenge',
        help='make ACME challenge available via DNS')
    parser_deploychallenge.set_defaults(func=deploy_challenge)
    parser_deploychallenge.add_argument(
        'domain',
        nargs=1,
        help="domain name to request certificate for")
    parser_deploychallenge.add_argument(
        'tokenfile',
        nargs=1,
        help="IGNORED")
    parser_deploychallenge.add_argument(
        'token',
        nargs=1,
        help="ACME-provided token")

    parser_cleanchallenge = subparsers.add_parser(
        'clean_challenge',
        help='remove ACME challenge from DNS')
    parser_cleanchallenge.set_defaults(func=clean_challenge)
    parser_cleanchallenge.add_argument(
        'domain',
        nargs=1,
        help="domain name for which to remove cetificate challenge")
    parser_cleanchallenge.add_argument(
        'tokenfile',
        nargs=1,
        help="IGNORED")
    parser_cleanchallenge.add_argument(
        'token',
        nargs=1,
        help="ACME-provided token")

    parser_deploycert = subparsers.add_parser(
        'deploy_cert',
        help='deploy certificate obtained from ACME (IGNORED)')
    parser_deploycert.set_defaults(func=deploy_cert)
    parser_deploycert.add_argument(
        'domain',
        nargs=1,
        help="domain name to deploy certificate for")
    parser_deploycert.add_argument(
        'keyfile',
        nargs=1,
        help="private certificate")
    parser_deploycert.add_argument(
        'certfile',
        nargs=1,
        help="public certificate")
    parser_deploycert.add_argument(
        'fullchainfile',
        nargs=1,
        help="full certificate chain")
    parser_deploycert.add_argument(
        'chainfile',
        nargs=1,
        help="certificate chain")
    parser_deploycert.add_argument(
        'timestamp',
        nargs=1,
        help="time stamp")

    parser_unchangedcert = subparsers.add_parser(
        'unchanged_cert',
        help='unchanged certificate obtained from ACME (IGNORED)')
    parser_unchangedcert.set_defaults(func=unchanged_cert)
    parser_unchangedcert.add_argument(
        'domain',
        nargs=1,
        help="domain name, for which the certificate hasn't changed")
    parser_unchangedcert.add_argument(
        'keyfile',
        nargs=1,
        help="private certificate")
    parser_unchangedcert.add_argument(
        'certfile',
        nargs=1,
        help="public certificate")
    parser_unchangedcert.add_argument(
        'fullchainfile',
        nargs=1,
        help="full certificate chain")
    parser_unchangedcert.add_argument(
        'chainfile',
        nargs=1,
        help="certificate chain")

    args = parser.parse_args()
    verbosity = args.verbose - args.quiet
    args.verbose = None
    args.quiet = None
    if verbosity:
        args.verbose = verbosity

    set_verbosity(verbosity)

    cfg = read_config(args)
    return (args.func, cfg)


if __name__ == '__main__':
    (fun, cfg) = parse_args()
    fun(cfg)
    sys.exit(0)
