# Installation

    apt install python3-yaml
    git clone https://gitlab.proikt.com/proikt/sshca
    cp src/sshca.py /usr/local/bin/sshca
    chown root. /usr/local/bin/sshca
    chmod 755 /usr/local/bin/sshca

# Configuration
See·[sshca.yaml.example](src/sshca.yaml.example)

# Usage
Example where you get the public key for signing

    ./sshca.py -p admin -i "John Doe" -k /path/to/key.pub

Example where profile contains the `generate_key` option to also handle key generation

    ./sshca.py -p borgbackup -i "client.example.com"