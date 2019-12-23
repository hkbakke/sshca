#!/usr/bin/env python3

import logging
import argparse
import random
import sys
import shutil
import subprocess
import os
from string import Template
from pathlib import Path

import yaml


LOGGER = logging.getLogger()


class SSHCA:
    def __init__(self, signing_key, revoked_keys, archive):
        self.signing_key = Path(signing_key)
        self.revoked_keys = Path(revoked_keys)
        self.archive = Path(archive)

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

    def _archive(self, signed_cert, identity, serial, host):
        if host:
            identity_dir = self.archive / 'host' / identity
        else:
            identity_dir = self.archive / 'user' / identity

        identity_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        archived_cert = identity_dir / Path('%s-cert.pub' % serial)
        shutil.copy(signed_cert, archived_cert)

    def _sign_key(self, public_key, identity, principals, validity, host, options, serial):
        cmd = [
            'ssh-keygen',
            '-s', str(self.signing_key),
            '-I', identity,
            '-z', str(serial),
        ]

        if validity is not None:
            cmd.extend([
                '-V', validity,
            ])

        if host:
            cmd.append('-h')
        else:
            cmd.extend([
                '-n', ','.join(principals),
                '-O', 'clear',
            ])

            for option in options:
                cmd.extend(['-O', option])

        cmd.append(str(public_key))
        LOGGER.debug('Command used for signing: %s', ' '.join(cmd))
        subprocess.run(cmd, check=True)
        return public_key.parent / ('%s-cert.pub' % public_key.stem)

    def sign_key(self, public_key, identity, principals, validity=None, host=False, options=None):
        if options is None:
            options = []

        serial = self._serial()
        signed_key = self._sign_key(public_key=public_key,
                                    identity=identity,
                                    principals=principals,
                                    validity=validity,
                                    host=host,
                                    options=options,
                                    serial=serial)
        self._archive(signed_key, identity, serial, host)
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


class SSHKey:
    def __init__(self, public_key, private_key=None, certificate=None):
        self.public_key = public_key
        self._private_key = None
        self._certificate = None

        if private_key:
            self.private_key = private_key

        if certificate:
            self.certificate = certificate

    @property
    def private_key(self):
        return self._private_key

    @private_key.setter
    def private_key(self, filename):
        self._private_key = Path(filename)

    @property
    def public_key(self):
        return self._public_key

    @public_key.setter
    def public_key(self, filename):
        self._public_key = Path(filename)

    @property
    def certificate(self):
        return self._certificate

    @certificate.setter
    def certificate(self, filename):
        self._certificate = Path(filename)


def generate_key(key_file, key_type=None):
    if key_type is None:
        key_type = 'ed25519'

    cmd = [
        'ssh-keygen',
        '-t', key_type,
        '-f', str(key_file),
    ]
    subprocess.run(cmd, check=True)
    key = SSHKey(private_key=key_file, public_key=key_file.with_suffix('.pub'))
    return key

def revoke_subcommand(args, ca, config):
    if not args.public_key:
        print('error: You must specify a public key or KRL specification file (-k/--public-key)')
        return os.EX_USAGE

    ca.revoke_key(args.public_key)
    return os.EX_OK

def sign_subcommand(args, ca, config):
    profile = config['profiles'][args.profile]
    validity = profile.get('validity', None)
    key_config = profile.get('generate_key', None)
    host_key = profile.get('host', False)
    principals = []
    options = []

    if not host_key:
        principals = profile['principals']
        options = profile.get('options', None)

    if key_config:
        templ = Template(key_config['filename'])
        filename = Path(templ.substitute(i=args.identity))

        if key_config.get('create_dirs', False):
            filename.parent.mkdir(parents=True, exist_ok=True)

        key = generate_key(filename, key_config.get('type', None))
    else:
        if not args.public_key:
            print('error: You must specify a public key (-k/--public-key)')
            return os.EX_USAGE

        key = SSHKey(public_key=args.public_key)

    print("Signing '%s' using '%s'..." % (key.public_key, ca.signing_key))
    ca.sign_key(public_key=key.public_key,
                identity=args.identity,
                principals=principals,
                validity=validity,
                options=options,
                host=host_key)

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

    signing_key = config.get('signing_key', '/etc/sshca/ca')
    revoked_keys = config.get('revoked_keys', '/var/lib/sshca/revoked_keys')
    archive = config.get('archive', '/var/lib/sshca/archive')
    ca = SSHCA(signing_key, revoked_keys, archive)

    return args.func(args, ca, config)

if __name__ == '__main__':
    sys.exit(main())
