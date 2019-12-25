#!/usr/bin/env python3

import logging
import argparse
import random
import sys
import shutil
import subprocess
import tempfile
from string import Template
from pathlib import Path
from datetime import datetime

import yaml


LOGGER = logging.getLogger()


class SSHCA:
    def __init__(self, ca_key=None, revoked_keys=None):
        self._ca_key = None
        self._revoked_keys = None

        if ca_key is None:
            self.ca_key = '/etc/sshca/ca'
        else:
            self.ca_key = ca_key

        if revoked_keys is None:
            self.revoked_keys = '/var/lib/sshca/revoked_keys'
        else:
            self.revoked_keys = revoked_keys

    @property
    def ca_key(self):
        return self._ca_key

    @ca_key.setter
    def ca_key(self, filename):
        self._ca_key = Path(filename)

    @property
    def revoked_keys(self):
        return self._revoked_keys

    @revoked_keys.setter
    def revoked_keys(self, filename):
        self._revoked_keys = Path(filename)

    @staticmethod
    def _serial():
        '''
        SSH certificates have a serial field of 64 bits
        '''
        return random.randint(1, 2**64)

    def sign_key(self, ssh_key, identity, principals=None, serial=None,
                 validity=None, host_key=False, options=None):
        if serial is None:
            serial = self._serial()

        cmd = [
            'ssh-keygen',
            '-s', str(self.ca_key),
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
        ssh_key.certificate = '%s-cert.pub' % ssh_key.public_key.with_suffix('')
        return ssh_key

    def revoke_key(self, ssh_key):
        cmd = [
            'ssh-keygen',
            '-k',
            '-s', str(self.ca_key),
            '-f', str(self.revoked_keys),
        ]

        if self.revoked_keys.is_file():
            cmd.append('-u')

        cmd.append(str(ssh_key.public_key))
        subprocess.run(cmd, check=True)


class SSHKey:
    def __init__(self, filename):
        self._private_key = None
        self._public_key = None
        self._certificate = None
        self._certinfo = None
        self.private_key = filename
        self.public_key = '%s.pub' % filename
        self.certificate = '%s-cert.pub' % filename

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

    @property
    def identity(self):
        info = self.certinfo()
        for line in info.splitlines():
            if line.strip().startswith('Key ID:'):
                return line.split(':', 1)[1].strip().lstrip('"').rstrip('"')
        raise ValueError("Could not find 'Key ID' in certficate info")

    @property
    def valid_from(self):
        info = self.certinfo()
        for line in info.splitlines():
            if line.strip().startswith('Valid:'):
                valid = line.split(':', 1)[1].strip()
                if valid == 'forever':
                    return None
                return datetime.strptime(valid.split()[1], '%Y-%m-%dT%H:%M:%S')
        raise ValueError("Could not find 'Valid' in certficate info")

    @property
    def valid_to(self):
        info = self.certinfo()
        for line in info.splitlines():
            if line.strip().startswith('Valid:'):
                valid = line.split(':', 1)[1].strip()
                if valid == 'forever':
                    return None
                return datetime.strptime(valid.split()[3], '%Y-%m-%dT%H:%M:%S')
        raise ValueError("Could not find 'Valid' in certficate info")

    @property
    def serial(self):
        info = self.certinfo()
        for line in info.splitlines():
            if line.strip().startswith('Serial:'):
                return int(line.split(':', 1)[1].strip())
        raise ValueError("Could not find 'Serial' in certficate info")

    @property
    def host_key(self):
        info = self.certinfo()
        for line in info.splitlines():
            if line.strip().startswith('Type:'):
                if 'host certificate' in line.split(':', 1)[1].strip():
                    return True
                return False
        raise ValueError("Could not find 'Type' in certficate info")

    def certinfo(self):
        if not self._certinfo:
            cmd = ['ssh-keygen', '-Lf', str(self.certificate)]
            p = subprocess.run(cmd,
                               capture_output=True,
                               universal_newlines=True,
                               check=True)
            self._certinfo = p.stdout
        return self._certinfo


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
        LOGGER.info("Archiving certificate '%s' to '%s'",
                    ssh_key.certificate,
                    archived_cert)
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
    ssh_key = SSHKey(filename)
    return ssh_key

def revoke_subcommand(args, config):
    if not args.public_key:
        print('error: You must specify a public key or KRL specification file (-k/--public-key)')
        return 2

    ssh_key = SSHKey(Path(args.public_key).with_suffix(''))
    ca_key = config.get('ca_key')
    revoked_keys = config.get('revoked_keys')
    ca = SSHCA(ca_key, revoked_keys)
    ca.revoke_key(ssh_key)
    return 0

def sign_subcommand(args, config):
    profile = config['profiles'][args.profile]
    validity = profile.get('validity')
    key_config = profile.get('generate_key')
    host_key = profile.get('host_key', False)
    principals = profile.get('principals')
    options = profile.get('options')

    with tempfile.TemporaryDirectory() as tmpdir:
        if key_config:
            templ = Template(key_config['filename'])
            private_key = Path(templ.substitute(i=args.identity))
            private_key_tmp = Path(tmpdir) / private_key.name
            ssh_key = generate_key(private_key_tmp,
                                   key_config.get('type'),
                                   key_config.get('bits'))
        else:
            if not args.public_key:
                print('error: You must specify a public key (-k/--public-key)')
                return 2

            public_key = Path(args.public_key)
            public_key_tmp = Path(tmpdir) / public_key.name
            # This copy is only needed because ssh-keygen outputs the
            # certificate in the same directory as the public key.
            shutil.copy(public_key, public_key_tmp)
            ssh_key = SSHKey(public_key_tmp.with_suffix(''))

        ca_key = config.get('ca_key')
        ca = SSHCA(ca_key)
        print("Signing '%s' using '%s'..." % (ssh_key.public_key, ca.ca_key))
        ssh_key_signed = ca.sign_key(ssh_key=ssh_key,
                                     identity=args.identity,
                                     principals=principals,
                                     validity=validity,
                                     options=options,
                                     host_key=host_key)

        archive = config.get('archive')
        cert_archive = CertArchive(archive)
        cert_archive.add(ssh_key_signed)

        # Add to final destination after the certificate is archived to
        # ensure no certificate is issued without we having a copy of the
        # certificate for revokation purposes.
        if key_config:
            if key_config.get('create_dirs', False):
                private_key.parent.mkdir(parents=True, exist_ok=True)

            shutil.copy(ssh_key_signed.private_key, private_key.parent)
            shutil.copy(ssh_key_signed.public_key, private_key.parent)
            shutil.copy(ssh_key_signed.certificate, private_key.parent)
        else:
            shutil.copy(ssh_key_signed.certificate, public_key.parent)

        print(ssh_key_signed.certinfo())

    return 0

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

    try:
        return args.func(args, config)
    except subprocess.CalledProcessError as e:
        LOGGER.error(e)
        return 1

if __name__ == '__main__':
    sys.exit(main())
