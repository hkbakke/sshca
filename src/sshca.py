#!/usr/bin/env python3

import logging
import argparse
import random
import sys
import shutil
import subprocess
import re
import os
from string import Template
from datetime import timedelta
from pathlib import Path

import yaml


LOGGER = logging.getLogger()


class SSHCA:
    def __init__(self, signing_key, signed_log, revoked_keys, archive):
        self.signing_key = Path(signing_key)
        self.signed_log = Path(signed_log)
        self.revoked_keys = Path(revoked_keys)
        self.archive = Path(archive)

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

    def _archive(self, signed_cert, identity, serial):
        identity_dir = self.archive / identity
        identity_dir.mkdir(exist_ok=True)
        archived_cert = identity_dir / Path('%s-cert.pub' % serial)
        shutil.copy(signed_cert, archived_cert)

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
        self._archive(signed_key, identity, serial)
        self._log_signed(signed_key)
        return signed_key

    def revoke_key(self, public_key):
        cmd = [
            'ssh-keygen',
            '-k',
            '-s', str(self.signing_key),
            '-f', str(self.revoked_keys),
        ]

        if self.revoked_keys.is_file():
            cmd.append('-u')

        cmd.append(public_key)
        subprocess.run(cmd, check=True)

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

def revoke_subcommand(args, ca, config):
    if not args.public_key:
        print('error: You must specify a public key or KRL specification file (-k/--public-key)')
        return os.EX_USAGE

    ca.revoke_key(args.public_key)
    return os.EX_OK

def sign_subcommand(args, ca, config):
    profile = config['profiles'][args.profile]
    principals = profile['principals']
    validity = profile.get('validity', None)
    options = profile.get('options', None)
    key_config = profile.get('generate_key', None)

    if key_config:
        templ = Template(key_config['filename'])
        filename = Path(templ.substitute(i=args.identity))

        if key_config.get('create_dirs', False):
            filename.parent.mkdir(parents=True, exist_ok=True)

        public_key = generate_key(filename, key_config.get('type', None))
    else:
        if not args.public_key:
            print('error: You must specify a public key (-k/--public-key)')
            return os.EX_USAGE

        public_key = Path(args.public_key)

    print("Signing '%s' using '%s'..." % (public_key, ca.signing_key))
    ca.sign_key(public_key, args.identity, principals, validity, options)
    return os.EX_OK

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default='/etc/sshca/sshca.yaml')
    parser.add_argument('-v', '--verbose', action='store_true')
    subparsers = parser.add_subparsers(title='subcommands', dest='subcommand')
    sign_parser = subparsers.add_parser('sign', help='sign public key')
    sign_parser.add_argument('-p', '--profile', required=True)
    sign_parser.add_argument('-i', '--identity', required=True)
    sign_parser.add_argument('-k', '--public-key')
    sign_parser.set_defaults(func=sign_subcommand)
    revoke_parser = subparsers.add_parser('revoke', help='revoke public key')
    revoke_parser.add_argument('-k', '--public-key')
    revoke_parser.set_defaults(func=revoke_subcommand)
    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    if args.verbose:
        log_level = 'DEBUG'
    else:
        log_level = 'INFO'

    LOGGER.setLevel(log_level)
    log = config.get('log', '/var/log/sshca/sshca.log')
    service_log = logging.FileHandler(log)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    service_log.setFormatter(formatter)
    LOGGER.addHandler(service_log)

    signed_log = config.get('signed_log', '/var/log/sshca/signed.log')
    signing_key = config.get('signing_key', '/etc/sshca/ca')
    revoked_keys = config.get('revoked_keys', '/var/lib/sshca/revoked_keys')
    archive = config.get('archive', '/var/lib/sshca/archive')
    ca = SSHCA(signing_key, signed_log, revoked_keys, archive)

    return args.func(args, ca, config)

if __name__ == '__main__':
    sys.exit(main())
