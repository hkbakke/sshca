#!/usr/bin/env python3

import logging
import argparse
import os
import grp
import random
import tempfile
import sys
import subprocess
import re
from string import Template
from datetime import timedelta, datetime
from pathlib import Path

import yaml


LOGGER = logging.getLogger()


class SSHCA:
    def __init__(self, signing_key, signed_log):
        self.signing_key = Path(signing_key)
        self.signed_log=signed_log

    @staticmethod
    def _to_timedelta(value):
        qualifiers = {
            's': 1,
            'm': 60,
            'h': 3600,
            'd': 86400,
            'w': 604800,
        }
        intervals = re.findall(r'\d+\D', value)
        seconds = 0
        for i in intervals:
            number, qualifier = re.search(r'(\d+)(\D)', i).groups()
            seconds += int(number) * qualifiers[qualifier.lower()]
        return timedelta(seconds=seconds)

    @staticmethod
    def _serial(length=12):
        '''
        19 digits seems to be the maximum serial length in signed SSH keys
        '''
        return random.randint(1,10**length)

    def _log_signed(self, fingerprint, identity, serial, principals, validity):
        timestamp = datetime.now()
        with open(self.signed_log, 'a') as f:
            f.write('%s | %s | %s | %s | %s | %s\n' % (timestamp,
                                                       fingerprint,
                                                       identity,
                                                       serial,
                                                       ','.join(principals),
                                                       validity))

    def _sign_key(self, public_key, identity, principals, validity, options, serial):
        validity_seconds = int(self._to_timedelta(validity).total_seconds())
        cmd = [
            'ssh-keygen',
            '-s', str(self.signing_key),
            '-I', identity,
            '-n', ','.join(principals),
            '-V', '+%ds' % validity_seconds,
            '-z', str(serial),
            '-O', 'clear',
        ]

        for in_option in options:
            s = Template(in_option)
            option = s.substitute(i=identity)
            cmd.extend(['-O', option])

        cmd.append(str(public_key))
        LOGGER.debug('Command used for signing: %s', ' '.join(cmd))
        subprocess.run(cmd, check=True)
        return public_key.parent / ('%s-cert.pub' % public_key.stem)

    def sign_key(self, public_key, identity, principals, validity='1y', options=None):
        if options is None:
            options = []

        serial = self._serial()
        signed_key = self._sign_key(Path(public_key), identity, principals,
                                    validity, options, serial)
        fp = self._get_fingerprint(signed_key)
        self._log_signed(fp, identity, serial, principals, validity)
        return signed_key

    @staticmethod
    def _get_fingerprint(cert):
        cmd = ['ssh-keygen', '-lf', cert]
        p = subprocess.run(cmd, capture_output=True, universal_newlines=True, check=True)
        return p.stdout


def certinfo(cert):
    cmd = ['ssh-keygen', '-Lf', cert]
    p = subprocess.run(cmd, capture_output=True, universal_newlines=True, check=True)
    return p.stdout

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default='/etc/sshca/sshca.yaml')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-p', '--profile', required=True)
    parser.add_argument('-i', '--identity', required=True)
    parser.add_argument('-k', '--public-key', required=True)
    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    log = config.get('log', '/var/log/sshca/sshca.log')
    signed_log = config.get('signed_log', '/var/log/sshca/signed.log')
    signing_key = config.get('signing_key', '/etc/sshca/ca')
    principals = config['profiles'][args.profile]['principals']
    validity = config['profiles'][args.profile]['validity']
    options = config['profiles'][args.profile].get('options', [])

    if args.verbose:
        log_level = 'DEBUG'
    else:
        log_level = 'INFO'

    LOGGER.setLevel(log_level)
    service_log = logging.FileHandler(log)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    service_log.setFormatter(formatter)
    LOGGER.addHandler(service_log)

    ca = SSHCA(signing_key, signed_log)
    signed_key = ca.sign_key(args.public_key, args.identity, principals,
                             validity, options)
    print(certinfo(signed_key))

if __name__ == '__main__':
    sys.exit(main())
