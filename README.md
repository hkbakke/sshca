# Installation

    sudo apt install python3-yaml
    git clone https://gitlab.proikt.com/proikt/sshca
    cd sshca
    ./install.sh

# Configuration
See [sshca.yaml.example](src/sshca.yaml.example)

# Usage
Example where you get the public key for signing

    sshca sign -p admin -i "John Doe" -k /path/to/key.pub

Example where profile contains the `generate_key` option to also handle key generation

    sshca sign -p borgbackup -i "client.example.com"

To revoke a certificate

    sshca revoke -k <public key or KRL specification file>
