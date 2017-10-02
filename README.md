# Iont detection tool

This tool is related to [ACM CCS 2017 conference paper #124 Return of the Coppersmith’s Attack: Practical Factorization of Widely Used RSA Moduli](https://crocs.fi.muni.cz/public/papers/rsa_ccs17).

It enables you to test public RSA keys for a presence of the described vulnerability.

Currently the tool supports the following key formats:

- X509 Certificate, DER encoded, one per file, *.der, *.crt
- X509 Certificate, PEM encoded, more per file, *.pem
- RSA PEM encoded private key, public key, more per file, *.pem (has to have correct header -----BEGIN RSA...)
- SSH public key, *.pub, starting with "ssh-rsa", one per line
- ASC encoded PGP key, *.pgp, *.asc. More per file, has to have correct header -----BEGIN PGP...
- APK android application, *.apk
- one modulus per line text file *.txt, modulus can be
    a) base64 encoded number, b) hex coded number, c) decimal coded number
- JSON file with moduli, one record per line, record with modulus has
    key "mod" (int, base64, hex, dec encoding supported)
    certificate(s) with key "cert" / array of certificates with key "certs" are supported, base64 encoded DER.
- LDIFF file - LDAP database dump. Any field ending with ";binary::" is attempted to decode as X509 certificate
- Java Key Store file (JKS). Tries empty password & some common, specify more with --jks-pass-file
- PKCS7 signature with user certificate

The detection tool is intentionally one-file implementation for easy integration / manipulation.

## Pip install

Install with pip (installs all dependencies)

```
pip install iont-detect
```

## Local install

Execute in the root folder of the package:

```
pip install --upgrade --find-links=. .
```

## Dependencies

It may be required to install additional dependencies so `pip` can install e.g. cryptography package.

CentOS / RHEL:

```
sudo yum install python-devel python-pip gcc gcc-c++ make automake autoreconf libtool openssl-devel libffi-devel dialog
```

Ubuntu:
```
sudo apt-get install python-pip python-dev build-essential libssl-dev libffi-dev
```

## Usage

To print the basic usage:

```
# If installed with pip / manually
iont-detect --help

# Without installation (can miss dependencies)
python fingerprint/detect.py
```

The testing tool accepts multiple file names / directories as the input argument.
It returns the report showing how many files has been fingerprinted (and which are those).

Example:

Running recursively on all my SSH keys and known_hosts:

```
$> iont-detect ~/.ssh
2017-10-16 13:39:21 [51272] INFO ### SUMMARY ####################
2017-10-16 13:39:21 [51272] INFO Records tested: 92
2017-10-16 13:39:21 [51272] INFO .. PEM certs: . . . 0
2017-10-16 13:39:21 [51272] INFO .. DER certs: . . . 0
2017-10-16 13:39:21 [51272] INFO .. RSA key files: . 16
2017-10-16 13:39:21 [51272] INFO .. PGP master keys: 0
2017-10-16 13:39:21 [51272] INFO .. PGP total keys:  0
2017-10-16 13:39:21 [51272] INFO .. SSH keys:  . . . 76
2017-10-16 13:39:21 [51272] INFO .. APK keys:  . . . 0
2017-10-16 13:39:21 [51272] INFO .. JSON keys: . . . 0
2017-10-16 13:39:21 [51272] INFO .. LDIFF certs: . . 0
2017-10-16 13:39:21 [51272] INFO .. JKS certs: . . . 0
2017-10-16 13:39:21 [51272] INFO No fingerprinted keys found (OK)
2017-10-16 13:39:21 [51272] INFO ################################
```


## Advanced installation methods

### Virtual environment

It is usually recommended to create a new python virtual environment for the project:

```
virtualenv ~/pyenv
source ~/pyenv/bin/activate
pip install --upgrade pip
pip install --upgrade --find-links=. .
```

### Separate Python 2.7.13

It won't work with lower Python version. Use `pyenv` to install a new Python version.
It internally downloads Python sources and installs it to `~/.pyenv`.

```
git clone https://github.com/pyenv/pyenv.git ~/.pyenv
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
exec $SHELL
pyenv install 2.7.13
pyenv local 2.7.13
```

