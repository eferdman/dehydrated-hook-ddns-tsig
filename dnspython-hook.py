#!/usr/bin/env python
#
# dnspython-hook - dns-01 Challenge Hook Script for dehydrated.sh
#
# This script uses the dnspython API to create and delete TXT records
# in order to prove ownership of a domain.
#
# Copyright (C) 2016 Elizabeth Ferdman https://eferdman.github.io
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

# Configure some basic logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

# Replace 10.0.0.1 with the IP address of your master server.
name_server_ip = '10.0.0.1'

# If necessary, replace HMAC_MD5 with HMAC_SHA1, HMAC_SHA224, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512
keyalgorithm = dns.tsig.HMAC_MD5

def get_key():
    import iscpy
    key_dict = {}
    key_file = os.environ.get('DDNS_HOOK_KEY_FILE')

    # Open the key file for reading
    f = open(key_file, 'rU')

    # Parse the key file
    parsed_key_file = iscpy.ParseISCString(f.read())

    # Grab the keyname, cut out the substring "key " and remove the extra quotes
    key_name = parsed_key_file.keys()[0][4:].strip('\"')

    # Grab the secret key
    secret = parsed_key_file.values()[0]['secret'].strip('\"')
    key_dict[key_name] = secret
    f.close()

    return key_dict

keyring = dns.tsigkeyring.from_text(get_key())

# Create a TXT record through the dnspython API
# Example code at https://github.com/rthalley/dnspython/blob/master/examples/ddns.py
def create_txt_record(domain_name, token):

    logger.info(" + Creating TXT record \"" + token + "\" for the domain _acme-challenge." + domain_name)
    update = dns.update.Update(domain_name, keyring=keyring, keyalgorithm=keyalgorithm)
    update.add('_acme-challenge', 300, 'TXT', token)

    # Attempt to add a TXT record
    try:
        response = dns.query.udp(update, name_server_ip, timeout=10)
    except DNSException as err:
        logger.error(err)

    # Wait for DNS record to propagate
    time.sleep(5)

    # Check if the TXT record was inserted
    try:
        answers = dns.resolver.query('_acme-challenge.' + domain_name, 'TXT')
    except DNSException as err:
        logger.error(err)
        sys.exit(1)
    else:
        txt_records = [txt_record.strings[0] for txt_record in answers]
        if token in txt_records:
            logger.info(" + TXT record successfully added!")
        else:
            logger.info(" + TXT record not added.")
            sys.exit(1)

# Delete the TXT record using the dnspython API
def delete_txt_record(domain_name, token):
    logger.info(" + Deleting TXT record \"" + token + "\" for the domain _acme-challenge." + domain_name)

    # Retrieve the specific TXT record
    txt_record = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, token)

    # Attempt to delete the TXT record
    update = dns.update.Update(domain_name, keyring=keyring, keyalgorithm=keyalgorithm)
    update.delete('_acme-challenge', txt_record)
    try:
        reponse = dns.query.udp(update, name_server_ip, timeout=10)
    except DNSException as err:
        logger.error(err)

    # Wait for DNS record to propagate
    time.sleep(5)

    # Check if the TXT record was successfully removed
    try:
        answers = dns.resolver.query('_acme-challenge.' + domain_name, 'TXT')
    except DNSException as err:
        logger.error(err)
        sys.exit(1)
    else:
        txt_records = [txt_record.strings[0] for txt_record in answers]
        if token in txt_records:
            logger.info(" + TXT record not successfully deleted.")
            sys.exit(1)
        else:
            logger.info(" + TXT record successfully deleted.")

def main(hook_stage, domain_name, token):
    logger.info(" + Dnsupdate.py executing " + hook_stage)

    if hook_stage == 'deploy_challenge':
        create_txt_record(domain_name, token)
    if hook_stage == 'clean_challenge':
        delete_txt_record(domain_name, token)

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[4])
