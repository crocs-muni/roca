# ROCA detection tool

[![Build Status](https://travis-ci.org/crocs-muni/roca.svg?branch=master)](https://travis-ci.org/crocs-muni/roca)


This tool is related to [ACM CCS 2017 conference paper #124 Return of the Coppersmith’s Attack: Practical Factorization of Widely Used RSA Moduli](https://crocs.fi.muni.cz/public/papers/rsa_ccs17).

It enables you to test public RSA keys for a presence of the described vulnerability.

*Update 4.11.2017*: Python 2.7, 3.4+ supported.

*Update 30.10.2017*: The [paper](https://crocs.fi.muni.cz/_media/public/papers/nemec_roca_ccs17_preprint.pdf) of the attack is already online,
 [ACM version](https://dl.acm.org/citation.cfm?id=3133969).

*Update 30.10.2017*: The discrete logarithm detector is now implemented in the Python and used as a default. It detects the structure
in the primes exploited by the factorizing algorithm.

Currently the tool supports the following key formats:

- X509 Certificate, DER encoded, one per file, `*.der`, `*.crt`
- X509 Certificate, PEM encoded, more per file, `*.pem`
- RSA PEM encoded private key, public key, more per file, `*.pem` (has to have correct header `-----BEGIN RSA...`)
- SSH public key, `*.pub`, starting with "ssh-rsa", one per line
- ASC encoded PGP key, `*.pgp`, `*.asc`. More per file, has to have correct header `-----BEGIN PGP...`
- APK android application, `*.apk`
- one modulus per line text file `*.txt`, modulus can be
    a) base64 encoded number, b) hex coded number, c) decimal coded number
- JSON file with moduli, one record per line, record with modulus has
    key "mod" (int, base64, hex, dec encoding supported)
    certificate(s) with key "cert" / array of certificates with key "certs" are supported, base64 encoded DER.
- LDIFF file - LDAP database dump. Any field ending with `;binary::` is attempted to decode as X509 certificate
- Java Key Store file (JKS). Tries empty password & some common, specify more with `--jks-pass-file`
- PKCS7 signature with user certificate

The detection tool is intentionally one-file implementation for easy integration / manipulation.

## False positive

False positive detection rates:

 * Moduli detector: 2^-27
 * Discrete logarithm detector: 2^-157

Discrete logarithm detector is implemented only in the Python code, used as the default detection method.

Java and C# code ports are unmaintained since the original publication and we don't plan to upgrade these
detectors to the more precise method. However PR are welcome!

## Online checker

https://keychest.net/roca

The online checker is using the discrete logarithm detector algorithm.

## Install with pip

Install the detector library + tool with `pip` (installs all dependencies):

```
pip install roca-detect
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
sudo apt-get install python-pip python-dev build-essential libssl-dev libffi-dev swig
```

## Usage

To print the basic usage:

```
# If installed with pip / manually
roca-detect --help

# Without installation (can miss dependencies)
python roca/detect.py
```

The testing tool accepts multiple file names / directories as the input argument.
It returns the report showing how many files has been fingerprinted (and which are those).

**Example (no vulnerabilities found):**

Running recursively on all my SSH keys and known_hosts:

<pre><code>
$> roca-detect ~/.ssh
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
2017-10-16 13:39:21 [51272] INFO .. PKCS7: . . . . . 0
<b>2017-10-16 13:39:21 [51272] INFO No fingerprinted keys found (OK)</b>
2017-10-16 13:39:21 [51272] INFO ################################
</code></pre>

**Example (vulnerabilities found):**

Running recursively on all my SSH keys and known_hosts:

<pre><code>
$> roca-detect ~/.ssh
<b>2017-10-16 13:39:21 [51272] WARNING Fingerprint found in the Certificate</b>
...
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
2017-10-16 13:39:21 [51272] INFO .. PKCS7: . . . . . 0
<b>2017-10-16 13:39:21 [51272] INFO Fingerprinted keys found: 1</b>
<b>2017-10-16 13:39:21 [51272] INFO WARNING: Potential vulnerability</b>
2017-10-16 13:39:21 [51272] INFO ################################
</code></pre>

## PGP key

In order to test your PGP key you can export it from your email client or download it from the PGP key server such as
https://pgp.mit.edu/

You can also use `gpg` command line utility to export your public key:

```bash
gpg --armor --export your@email.com > mykey.asc
```

## Advanced use case

Detection tool extracts information about the key which can be displayed:

```
roca-detect.py --dump --flatten --indent  ~/.ssh/
```

## TLS/SSL detection
The `roca-detect-tls` detects certificates from remote TLS/SSL ports. Provide a file with a newline-delimited list of `address:port` entries and use that file as input.

Example file: tls_list.txt
```
github.com:443
google.com:443
internal.example.com:8080
```

Then run:

`roca-detect-tls tls_list.txt`

## Fake moduli

It is possible to generate moduli that passes the moduli fingerprinting test but actually do not contain structure
the factorization algorithm is using. Dlog moduli test do not mark those as positive.

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

We tested tool with Python 2.7.13 and it works (see Travis for more info).
We have reports saying lower versions (<=2.6) do not work properly so we highly recommend using up to date Python 2.7

Use `pyenv` to install a new Python version locally if you cannot / don't want to update system Python.

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

### Python 3

Detection tools works also with Python 3.4+

### Docker container

Run via Docker container to avoid environment inconsistency. Dockerfile source can be audited at https://hub.docker.com/r/unnawut/roca-detect/.

```
docker run --rm -v /path/to/your/keys:/keys --network none unnawut/roca-detect
```

Make sure to use `--rm` and `--network none` flags to disable container's network connection and delete the container after running.


## Licensing

Code is licensed under permissive MIT license.

As there were requests on dual licensing under Apache 2.0 license (due to some doubts on compatibility) we are licensing
the code also under Apache 2.0 license.

Pick license that suits you better, either MIT or Apache 2.0.

## Language ports

This section contains links to different GIT repositories with language ports

- [Go](https://github.com/titanous/rocacheck)

