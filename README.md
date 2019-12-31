# SSHCA
sshca is a small utility to handle administration of SSH CAs. sshca uses a system based on profiles defined in YAML for repeatability. It also supports key generation and templated output paths to simplify generating keys and certificates for large amounts of hosts or users. sshca ensures all signed certificates are archived for revocation purposes, and it also handles revocation of certificates if needed. sshca is not aimed to be a service that end users interfaces with for getting short lived SSH certificates for authentication, for that use something like HashiCorp Vault, but rather to be used as a helper or automation tool when the system administrator want to generate keys and certificates from a central location, typically for distribution with a configuration management tool.

# Installation

    sudo apt install python3-yaml
    git clone https://github.com/hkbakke/sshca.git
    cd sshca
    ./install.sh

# Configuration
See [sshca.yaml.example](src/sshca.yaml.example)

# Usage
Create a CA key to use for signing if you don't have one from before

    ssh-keygen -t ed25519 -f /etc/sshca/ca

Example where you get the public key for signing

    sshca sign -p admin -i "John Doe" -k /path/to/key.pub

Example where profile contains the `generate_key` option to also handle key generation

    sshca sign -p borgbackup -i "client.example.com"

To revoke a certificate

    sshca revoke -k <public key or KRL specification file>
