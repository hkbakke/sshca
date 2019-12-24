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
    def __init__(self, signing_key=None, revoked_keys=None):
        self._signing_key = None
        self._revoked_keys = None

        if signing_key is None:
            self.signing_key = '/etc/sshca/ca'
        else:
            self.signing_key = signing_key

        if revoked_keys is None:
            self.revoked_keys = '/var/lib/sshca/revoked_keys'
        else:
            self.revoked_keys = revoked_keys

    @property
    def signing_key(self):
        return self._signing_key

    @signing_key.setter
    def signing_key(self, filename):
        self._signing_key = Path(filename)

    @property
    def revoked_keys(self):
        return self._revoked_keys

    @revoked_keys.setter
    def revoked_keys(self, filename):
        self._revoked_keys = Path(filename)

    @staticmethod
    def _serial(length=12):
        '''
        19 digits seems to be the maximum serial length in signed SSH keys
        '''
        return random.randint(1, 10**length)

    def sign_key(self, ssh_key, identity, principals=None, serial=None,
                 validity=None, host_key=False, options=None):
        if serial is None:
            serial = self._serial()

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

        if host_key:
            cmd.append('-h')

        if options is not None:
            cmd.extend([
                '-O', 'clear',
            ])

            for option in options:
                cmd.extend(['-O', option])

        if principals:
            cmd.extend([
                '-n', ','.join(principals),
            ])

        cmd.append(str(ssh_key.public_key))
        LOGGER.debug('Command used for signing: %s', ' '.join(cmd))
        subprocess.run(cmd, check=True)
        ssh_key.certificate = ssh_key.public_key.parent / Path('%s-cert.pub' % ssh_key.public_key.stem)
        ssh_key.identity = identity
        ssh_key.serial = serial
        ssh_key.validity = validity
        ssh_key.principals = principals
        ssh_key.host_key = host_key
        ssh_key.options = options
        return ssh_key

    def revoke_key(self, ssh_key):
        cmd = [
            'ssh-keygen',
            '-k',
            '-s', str(self.signing_key),
            '-f', str(self.revoked_keys),
        ]

        if self.revoked_keys.is_file():
            cmd.append('-u')

        cmd.append(str(ssh_key.public_key))
        subprocess.run(cmd, check=True)


class SSHKey:
    def __init__(self, public_key, private_key=None, certificate=None):
        self._public_key = None
        self._private_key = None
        self._certificate = None
        self.public_key = public_key
        self.identity = None
        self.serial = None
        self.validity = None
        self.options = None
        self.principals = None
        self.host_key = None

        if private_key is not None:
            self.private_key = private_key

        if certificate is not None:
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

    def certinfo(self):
        cmd = ['ssh-keygen', '-Lf', str(self.certificate)]
        p = subprocess.run(cmd, capture_output=True, universal_newlines=True, check=True)
        return p.stdout


class CertArchive:
    def __init__(self, archive=None):
        self._archive = None

        if archive is None:
            self.archive = '/var/lib/sshca/archive'
        else:
            self.archive = archive

    @property
    def archive(self):
        return self._archive

    @archive.setter
    def archive(self, directory):
        self._archive = Path(directory)

    def add(self, ssh_key):
        if ssh_key.host_key:
            identity_dir = self.archive / 'host' / ssh_key.identity
        else:
            identity_dir = self.archive / 'user' / ssh_key.identity

        identity_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        archived_cert = identity_dir / Path('%s-cert.pub' % ssh_key.serial)
        shutil.copy(ssh_key.certificate, archived_cert)


def generate_key(filename, key_type=None, bits=None):
    cmd = ['ssh-keygen']

    if bits is not None:
        cmd.extend(['-b', str(bits)])

    if key_type is not None:
        cmd.extend(['-t', key_type])

    cmd.extend([
        '-f', filename,
    ])
    subprocess.run(cmd, check=True)
    ssh_key = SSHKey(private_key=filename, public_key=filename.with_suffix('.pub'))
    return ssh_key

def revoke_subcommand(args, config):
    if not args.public_key:
        print('error: You must specify a public key or KRL specification file (-k/--public-key)')
        return os.EX_USAGE

    ssh_key = SSHKey(public_key=args.public_key)
    signing_key = config.get('signing_key')
    revoked_keys = config.get('revoked_keys')
    ca = SSHCA(signing_key, revoked_keys)
    ca.revoke_key(ssh_key)
    return os.EX_OK

def sign_subcommand(args, config):
    profile = config['profiles'][args.profile]
    validity = profile.get('validity')
    key_config = profile.get('generate_key')
    host_key = profile.get('host_key', False)
    principals = profile.get('principals')
    options = profile.get('options')

    if key_config:
        templ = Template(key_config['filename'])
        filename = Path(templ.substitute(i=args.identity))

        if key_config.get('create_dirs', False):
            filename.parent.mkdir(parents=True, exist_ok=True)

        ssh_key = generate_key(filename,
                               key_config.get('type'),
                               key_config.get('bits'))
    else:
        if not args.public_key:
            print('error: You must specify a public key (-k/--public-key)')
            return os.EX_USAGE

        ssh_key = SSHKey(public_key=args.public_key)

    signing_key = config.get('signing_key')
    ca = SSHCA(signing_key)
    print("Signing '%s' using '%s'..." % (ssh_key.public_key, ca.signing_key))
    ssh_key_signed = ca.sign_key(ssh_key=ssh_key,
                                 identity=args.identity,
                                 principals=principals,
                                 validity=validity,
                                 options=options,
                                 host_key=host_key)

    archive = config.get('archive')
    cert_archive = CertArchive(archive)
    cert_archive.add(ssh_key_signed)
    print(ssh_key.certinfo())
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

    return args.func(args, config)

if __name__ == '__main__':
    sys.exit(main())
