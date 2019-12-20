#!/bin/bash

SSHCA="/usr/local/bin/sshca"
SSHCA_DIR="/etc/sshca"

cp src/sshca.py ${SSHCA}
chown root. ${SSHCA}
chmod 755 ${SSHCA}

mkdir -p ${SSHCA_DIR}
chown root. ${SSHCA_DIR}
chmod 700 ${SSHCA_DIR}

cp src/sshca.yaml.example ${SSHCA_DIR}
