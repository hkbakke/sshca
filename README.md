# SSHCA
sshca is a small utility to handle administration of SSH CAs. sshca uses a
system based on profiles defined in YAML for repeatability. It also supports
key generation and templated output paths to simplify generating keys and
certificates for large amounts of hosts or users. sshca ensures all signed
certificates are archived for revocation purposes, and it also handles
revocation of certificates if needed. sshca is not aimed to be a service that
end users interface with for getting short lived SSH certificates for
authentication, for that use something like HashiCorp Vault, but rather to be
used as a helper or automation tool when the system administrator want to
generate keys and certificates from a central location, typically for
distribution with a configuration management tool.

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

In general this is the signing command format. The public key is not needed if
the profile has key generation configured.

    sshca sign <profile> "<identity>" [--public-key /path/to/key.pub]

Example where you sign a public key. The certificate is output in the same
folder as the public key as `<keyname>-cert.pub`.

    sshca sign admin "John Doe" --public-key /path/to/key.pub

To revoke a certificate

    sshca revoke <certificate file>

List signed certificates with validity and revocation status. To list
certificate info for the certificates add the `--info` argument.

    sshca show <certificate type> "<identity glob pattern>" [--serial "<serial glob pattern>"] [--info]
