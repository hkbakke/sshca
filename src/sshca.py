#!/usr/bin/env python3

import logging
import argparse
import random
import sys
import shutil
import subprocess
import tempfile
import itertools
from string import Template
from pathlib import Path
from datetime import datetime, timedelta

import yaml


# Default values
REVOKED_KEYS = '/var/lib/sshca/revoked_keys'
REVOKED_HOST_KEYS = '/var/lib/sshca/revoked_host_keys'
CA_KEY = '/etc/sshca/ca'
ARCHIVE = '/var/lib/sshca/archive'

LOGGER = logging.getLogger()


class SSHCA:
    def __init__(self, ca_key):
        self.ca_key = Path(ca_key)

    @staticmethod
    def _serial():
        '''
        SSH certificates have a serial field of 64 bits
        '''
        return random.randint(1, 2**64)

    def sign_key(self, ssh_key, identity, principals=None, serial=None,
                 validity=None, cert_type=None, options=None):
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

        if cert_type == 'host':
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


class SSHKey:
    def __init__(self, private_key=None, public_key=None, certificate=None):
        if not any([private_key, public_key, certificate]):
            raise ValueError('At least one of private_key, public_key or certificate must be set')

        self._private_key = None
        self._public_key = None
        self._certificate = None
        self._certinfo = None

        if private_key is not None:
            self.private_key = private_key

        if public_key is not None:
            self.public_key = public_key

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
        if not self._public_key:
            if self.private_key:
                self.public_key = self.private_key.with_suffix('.pub')
        return self._public_key

    @public_key.setter
    def public_key(self, filename):
        self._public_key = Path(filename)

    @property
    def certificate(self):
        if not self._certificate:
            if self.public_key:
                self.certificate = '%s-cert.pub' % self.public_key.with_suffix('')
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
        raise ValueError("Could not find 'Key ID' in certificate info")

    @property
    def valid_from(self):
        info = self.certinfo()
        for line in info.splitlines():
            if line.strip().startswith('Valid:'):
                valid = line.split(':', 1)[1].strip()
                if valid == 'forever':
                    from_date = datetime.min
                else:
                    from_date = datetime.strptime(valid.split()[1], '%Y-%m-%dT%H:%M:%S')
                return from_date
        raise ValueError("Could not find 'Valid' in certificate info")

    @property
    def valid_to(self):
        info = self.certinfo()
        for line in info.splitlines():
            if line.strip().startswith('Valid:'):
                valid = line.split(':', 1)[1].strip()
                if valid == 'forever':
                    to_date = datetime.max
                else:
                    to_date = datetime.strptime(valid.split()[3], '%Y-%m-%dT%H:%M:%S')
                return to_date

        raise ValueError("Could not find 'Valid' in certificate info")

    @property
    def serial(self):
        info = self.certinfo()
        for line in info.splitlines():
            if line.strip().startswith('Serial:'):
                return int(line.split(':', 1)[1].strip())
        raise ValueError("Could not find 'Serial' in certificate info")

    @property
    def cert_type(self):
        info = self.certinfo()
        for line in info.splitlines():
            if line.strip().startswith('Type:'):
                if 'host certificate' in line.split(':', 1)[1].strip():
                    return 'host'
                if 'user certificate' in line.split(':', 1)[1].strip():
                    return 'user'
                raise ValueError("Unknown certificate type")
        raise ValueError("Could not find 'Type' in certificate info")

    def certinfo(self):
        if not self._certinfo:
            cmd = ['ssh-keygen', '-Lf', str(self.certificate)]
            p = subprocess.run(cmd,
                               capture_output=True,
                               universal_newlines=True,
                               check=True)
            self._certinfo = p.stdout
        return self._certinfo

    def is_expired(self):
        return self.valid_to < datetime.now()


class RevocationList:
    def __init__(self, filename):
        self.filename = Path(filename)

    def add(self, ssh_key):
        cmd = [
            'ssh-keygen',
            '-k',
            '-f', str(self.filename),
        ]

        if self.filename.is_file():
            cmd.append('-u')

        cmd.append(str(ssh_key.certificate))
        subprocess.run(cmd, check=True)

    def is_revoked(self, ssh_key):
        cmd = [
            'ssh-keygen',
            '-Qf',
            str(self.filename),
            str(ssh_key.certificate)
        ]

        try:
            subprocess.run(cmd,
                           capture_output=True,
                           universal_newlines=True,
                           check=True)
        except subprocess.CalledProcessError as e:
            if 'REVOKED' in e.stdout:
                return True
            raise
        return False


class Archive:
    def __init__(self, path):
        self.path = Path(path)

    def add(self, ssh_key):
        identity_dir = self.path / ssh_key.cert_type / ssh_key.identity
        identity_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        archived_cert = identity_dir / Path('%s-cert.pub' % ssh_key.serial)
        LOGGER.info("Archiving certificate '%s' to '%s'",
                    ssh_key.certificate,
                    archived_cert)
        shutil.copy(ssh_key.certificate, archived_cert)

    def disk_usage(self):
        cmd = ['du', '-s', '--block-size=1', str(self.path)]
        p = subprocess.run(cmd,
                           capture_output=True,
                           universal_newlines=True,
                           check=True)
        return int(p.stdout.split()[0])

    def get_certs(self,
                  cert_type,
                  identity_pattern=None,
                  serial_pattern=None,
                  expiry_within=None,
                  exclude_expired=None,
                  exclude_valid=None):
        if identity_pattern is None:
            identity_pattern = '*'

        if serial_pattern is None:
            serial_pattern = '*'

        if exclude_expired is None:
            exclude_expired = False

        if exclude_valid is None:
            exclude_valid = False

        identities = (self.path / Path(cert_type)).glob(identity_pattern)
        for identity in identities:
            for cert in identity.glob('%s-cert.pub' % serial_pattern):
                ssh_key = SSHKey(certificate=cert)

                if exclude_expired:
                    if ssh_key.is_expired():
                        continue

                if exclude_valid:
                    if not ssh_key.is_expired():
                        continue

                if expiry_within is not None:
                    if ssh_key.is_expired() or ssh_key.valid_to > datetime.now() + timedelta(days=expiry_within):
                        continue

                yield ssh_key


def generate_key(filename, key_type=None, bits=None, comment=None, password=None):
    cmd = ['ssh-keygen']

    if bits is not None:
        cmd.extend(['-b', str(bits)])

    if key_type is not None:
        cmd.extend(['-t', key_type])

    if comment is not None:
        cmd.extend(['-C', comment])

    if password is not None:
        cmd.extend(['-N', password])

    cmd.extend([
        '-f', filename,
    ])
    subprocess.run(cmd, check=True)
    ssh_key = SSHKey(private_key=filename)
    return ssh_key

def archive_subcommand(args, config):
    archive_path = config.get('archive', ARCHIVE)
    archive = Archive(archive_path)

    if args.purge_expired:
        expired_host_certs = archive.get_certs(cert_type='host', exclude_valid=True)
        expired_user_certs = archive.get_certs(cert_type='user', exclude_valid=True)

        for i in itertools.chain(expired_host_certs, expired_user_certs):
            LOGGER.warning("Purging expired certificate '%s' from archive", i.certificate)
            i.certificate.unlink()
    else:
        host_certs = len(list(archive.get_certs(cert_type='host')))
        user_certs = len(list(archive.get_certs(cert_type='user')))
        size = archive.disk_usage()

        print('Archive path: %s' % archive_path)
        print('Archive size: %.2fM' % float(size / 1024 ** 2))
        print('Number of host certificates: %d' % host_certs)
        print('Number of user certificates: %d' % user_certs)

    return 0

def show_subcommand(args, config):
    archive_path = config.get('archive', ARCHIVE)
    archive = Archive(archive_path)
    certs = archive.get_certs(args.certtype,
                              args.identity,
                              args.serial,
                              args.expiry_within,
                              args.exclude_expired)

    revoked_keys = config.get('revoked_keys', REVOKED_KEYS)
    rl = RevocationList(revoked_keys)
    revoked_host_keys = config.get('revoked_host_keys', REVOKED_HOST_KEYS)
    host_rl = RevocationList(revoked_host_keys)

    for cert in certs:
        validity = 'VALID'
        if cert.is_expired():
            validity = 'EXPIRED'

        valid_to = cert.valid_to
        if valid_to == datetime.max:
            expiry = 'never'
        else:
            expiry = cert.valid_to

        if cert.cert_type == 'host':
            if host_rl.is_revoked(cert):
                if args.exclude_revoked:
                    continue
                validity = 'REVOKED'
        else:
            if rl.is_revoked(cert):
                if args.exclude_revoked:
                    continue
                validity = 'REVOKED'

        if args.info:
            print(cert.certinfo())
        else:
            print('{:<19}\t{:<19}\t{:<7}\t{}'.format(cert.serial,
                                                     str(expiry),
                                                     validity,
                                                     cert.identity))
    return 0

def revoke_subcommand(args, config):
    ssh_key = SSHKey(certificate=args.certificate)

    if ssh_key.cert_type == 'host':
        revoked_keys = config.get('revoked_host_keys', REVOKED_HOST_KEYS)
    else:
        revoked_keys = config.get('revoked_keys', REVOKED_KEYS)

    rl = RevocationList(revoked_keys)
    rl.add(ssh_key)
    return 0

def sign_subcommand(args, config):
    profile = config['profiles'][args.profile]
    validity = profile.get('validity')
    key_config = profile.get('generate_key')
    cert_type = profile.get('cert_type', 'user')
    principals = profile.get('principals')
    options = profile.get('options')
    pre_expiry_renewal = profile.get('pre_expiry_renewal', 30)

    if key_config:
        templ = Template(key_config['filename'])
        private_key = templ.substitute(i=args.identity)
        ssh_key = SSHKey(private_key=private_key)
    else:
        if not args.public_key:
            print('ERROR: You must specify a public key (-k/--public-key)')
            return 2

        ssh_key = SSHKey(public_key=args.public_key)

    LOGGER.debug('pre_expiry_renewal is set to %s', pre_expiry_renewal)

    if not args.force and pre_expiry_renewal and ssh_key.certificate.is_file():
        LOGGER.info("Checking expiry information for existing certificate in '%s'", ssh_key.certificate)
        if ssh_key.is_expired():
            LOGGER.info('Existing certificate has expired. Continuing...')
        elif ssh_key.valid_to - datetime.now() > timedelta(days=pre_expiry_renewal):
            LOGGER.info('There are more than %s days until the existing certificate expires. Skipping.', pre_expiry_renewal)
            return 0

    with tempfile.TemporaryDirectory() as tmpdir:
        if key_config:
            key_name = Path(tmpdir) / ssh_key.private_key.name
            LOGGER.info("Generating a new key in '%s'...", key_name)
            ssh_key_tmp = generate_key(filename=key_name,
                                       key_type=key_config.get('key_type'),
                                       bits=key_config.get('bits'),
                                       comment=key_config.get('comment'),
                                       password=key_config.get('password'))
        else:
            ssh_key_tmp = SSHKey(Path(tmpdir) / ssh_key.public_key.name)

            # This copy is only needed because ssh-keygen outputs the
            # certificate in the same directory as the public key.
            shutil.copy(ssh_key.public_key, ssh_key_tmp.public_key)

        if args.principals:
            principals.extend(args.principals.split(','))

        ca_key = profile.get('ca_key', config.get('ca_key', CA_KEY))
        ca = SSHCA(ca_key)
        LOGGER.info("Signing '%s' using '%s'...", ssh_key.public_key, ca.ca_key)
        ssh_key_signed = ca.sign_key(ssh_key=ssh_key_tmp,
                                     identity=args.identity,
                                     principals=principals,
                                     validity=validity,
                                     options=options,
                                     cert_type=cert_type)

        archive_path = config.get('archive', ARCHIVE)
        archive = Archive(archive_path)
        archive.add(ssh_key_signed)

        if key_config:
            if key_config.get('create_dirs', False):
                ssh_key.private_key.parent.mkdir(parents=True, exist_ok=True)

            shutil.copy(ssh_key_signed.private_key, ssh_key.private_key)
            shutil.copy(ssh_key_signed.public_key, ssh_key.public_key)

        shutil.copy(ssh_key_signed.certificate, ssh_key.certificate)
        LOGGER.info(ssh_key.certinfo())

    return 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default='/etc/sshca/sshca.yaml')
    parser.add_argument('-v', '--verbose', action='store_true')
    subparsers = parser.add_subparsers(title='subcommands', dest='subcommand')
    sign_parser = subparsers.add_parser('sign', help='sign public key')
    sign_parser.add_argument('profile')
    sign_parser.add_argument('identity')
    sign_parser.add_argument('-k', '--public-key')
    sign_parser.add_argument('-n', '--principals',
                             help='comma separated list of principals to append to profile principals')
    sign_parser.add_argument('-f', '--force', action='store_true',
                             help='always renew certificate')
    sign_parser.set_defaults(func=sign_subcommand)
    revoke_parser = subparsers.add_parser('revoke', help='revoke certificate')
    revoke_parser.add_argument('certificate', help='certificate file to revoke')
    revoke_parser.set_defaults(func=revoke_subcommand)
    show_parser = subparsers.add_parser('show', help='show signed certificates info')
    show_parser.add_argument('certtype', help='certificate type',
                             choices=['user', 'host'])
    show_parser.add_argument('identity', help='glob match pattern')
    show_parser.add_argument('-s', '--serial', help='glob match pattern')
    show_parser.add_argument('--expiry-within', metavar='DAYS', type=int,
                             help='only list certificates expiring within a certain number of days')
    show_parser.add_argument('--exclude-expired', action='store_true')
    show_parser.add_argument('--exclude-revoked', action='store_true')
    show_parser.add_argument('-i', '--info', help='show certificate info',
                             action='store_true')
    show_parser.set_defaults(func=show_subcommand)
    archive_parser = subparsers.add_parser('archive', help='archive maintenance')
    archive_parser.add_argument('--purge-expired', action='store_true',
                                help='purge expired certificates')
    archive_parser.set_defaults(func=archive_subcommand)
    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    if args.verbose:
        log_level = 'DEBUG'
    else:
        log_level = 'INFO'

    LOGGER.setLevel(log_level)
    log = config.get('log', '/var/log/sshca/sshca.log')
    logfile = logging.FileHandler(log)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    logfile.setFormatter(formatter)
    ch = logging.StreamHandler()
    LOGGER.addHandler(logfile)
    LOGGER.addHandler(ch)

    try:
        return args.func(args, config)
    except subprocess.CalledProcessError as e:
        LOGGER.error(e)
        return 1

if __name__ == '__main__':
    sys.exit(main())
