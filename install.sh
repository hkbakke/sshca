#!/bin/bash

SSHCA="/usr/local/bin/sshca"
SSHCA_DIR="/etc/sshca"
ARCHIVE_DIR="/var/lib/sshca/archive"
LOG_DIR="/var/log/sshca"

set -e

cp src/sshca.py ${SSHCA}
chown root. ${SSHCA}
chmod 755 ${SSHCA}

mkdir -p ${SSHCA_DIR}
chown root. ${SSHCA_DIR}
chmod 700 ${SSHCA_DIR}

mkdir -p ${ARCHIVE_DIR}
chown root. ${ARCHIVE_DIR}
chmod 700 ${ARCHIVE_DIR}

mkdir -p ${LOG_DIR}
chown root. ${LOG_DIR}
chmod 700 ${LOG_DIR}

cp src/sshca.yaml.example ${SSHCA_DIR}
