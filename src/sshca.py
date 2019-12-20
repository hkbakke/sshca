#!/usr/bin/env python3

import logging
import argparse
import random
import sys
import subprocess
import re
import os
from string import Template
from datetime import timedelta
from pathlib import Path

import yaml


LOGGER = logging.getLogger()


class SSHCA:
    def __init__(self, signing_key, signed_log):
        self.signing_key = Path(signing_key)
        self.signed_log = signed_log

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
        return random.randint(1, 10**length)

    @staticmethod
    def certinfo(cert):
        cmd = ['ssh-keygen', '-Lf', cert]
        p = subprocess.run(cmd, capture_output=True, universal_newlines=True, check=True)
        return p.stdout

    def _log_signed(self, signed_cert):
        with open(self.signed_log, 'a') as f:
            f.write('%s\n%s\n' % (self.certinfo(signed_cert).strip(), '-' * 3))

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

        for option in options:
            cmd.extend(['-O', option])

        cmd.append(str(public_key))
        LOGGER.debug('Command used for signing: %s', ' '.join(cmd))
        subprocess.run(cmd, check=True)
        return public_key.parent / ('%s-cert.pub' % public_key.stem)

    def sign_key(self, public_key, identity, principals, validity=None, options=None):
        if options is None:
            options = []

        if validity is None:
            validity = '1y'

        serial = self._serial()
        signed_key = self._sign_key(public_key, identity, principals, validity,
                                    options, serial)
        self._log_signed(signed_key)
        return signed_key


def generate_key(key_file, key_type=None):
    if key_type is None:
        key_type = 'ed25519'

    cmd = [
        'ssh-keygen',
        '-t', key_type,
        '-f', str(key_file),
    ]
    subprocess.run(cmd, check=True)
    return key_file.with_suffix('.pub')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default='/etc/sshca/sshca.yaml')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-p', '--profile', required=True)
    parser.add_argument('-i', '--identity', required=True)
    parser.add_argument('-k', '--public-key')
    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    log = config.get('log', '/var/log/sshca/sshca.log')
    signed_log = config.get('signed_log', '/var/log/sshca/signed.log')
    signing_key = config.get('signing_key', '/etc/sshca/ca')
    profile = config['profiles'][args.profile]
    principals = profile['principals']
    validity = profile.get('validity', None)
    options = profile.get('options', None)
    key_config = profile.get('generate_key', None)

    if args.verbose:
        log_level = 'DEBUG'
    else:
        log_level = 'INFO'

    LOGGER.setLevel(log_level)
    service_log = logging.FileHandler(log)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    service_log.setFormatter(formatter)
    LOGGER.addHandler(service_log)

    if key_config:
        templ = Template(key_config['filename'])
        filename = Path(templ.substitute(i=args.identity))

        if key_config.get('create_dirs', False):
            filename.parent.mkdir(parents=True, exist_ok=True)

        public_key = generate_key(filename, key_config.get('type', None))
    else:
        if not args.public_key:
            print('error: You must specify the public key (-k/--public-key)')
            return os.EX_USAGE

        public_key = Path(args.public_key)

    ca = SSHCA(signing_key, signed_log)
    print("Signing '%s' using '%s'..." % (public_key, signing_key))
    ca.sign_key(public_key, args.identity, principals, validity, options)

    return os.EX_OK

if __name__ == '__main__':
    sys.exit(main())
