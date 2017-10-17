#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Key fingerprinting

The fingerprinter supports the following formats:

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
    - PKCS7 signature with user certificate.

Script requirements:

    - Tested on Python 2.7.13
    - pip install cryptography pgpdump coloredlogs future six pycrypto>=2.6 python-dateutil pyx509_ph4 apk_parse_ph4 pyjks M2Crypto
    - some system packages are usually needed for pip to install dependencies (like gcc):
        sudo sudo yum install python-devel python-pip gcc gcc-c++ make automake autoreconf libtool openssl-devel libffi-devel dialog
        sudo apt-get install python-pip python-dev build-essential libssl-dev libffi-dev

"""

from future.utils import iteritems
import json
import argparse
import logging
import coloredlogs
import types
import base64
import hashlib
import sys
import os
import re
import binascii
import collections
import traceback
import datetime
from math import ceil, log


#            '%(asctime)s %(hostname)s %(name)s[%(process)d] %(levelname)s %(message)s'
LOG_FORMAT = '%(asctime)s [%(process)d] %(levelname)s %(message)s'


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO, fmt=LOG_FORMAT)


#
# Helper functions & classes
#

def strip_hex_prefix(x):
    """
    Strips possible hex prefixes from the strings
    :param x:
    :return:
    """
    if x.startswith('0x'):
        return x[2:]
    if x.startswith('\\x'):
        return x[2:]
    return x


def error_message(e, message=None, cause=None):
    """
    Formats exception message + cause
    :param e:
    :param message:
    :param cause:
    :return: formatted message, includes cause if any is set
    """
    if message is None and cause is None:
        return None
    elif message is None:
        return '%s, caused by %r' % (e.__class__, cause)
    elif cause is None:
        return message
    else:
        return '%s, caused by %r' % (message, cause)


def format_pgp_key(key):
    """
    Formats PGP key in 16hex digits
    :param key:
    :return:
    """
    if key is None:
        return None
    if isinstance(key, (types.IntType, types.LongType)):
        return '%016x' % key
    elif isinstance(key, types.ListType):
        return [format_pgp_key(x) for x in key]
    else:
        key = key.strip()
        key = strip_hex_prefix(key)
        return format_pgp_key(int(key, 16))


def defval(val, default=None):
    """
    Returns val if is not None, default instead
    :param val:
    :param default:
    :return:
    """
    return val if val is not None else default


def defvalkey(js, key, default=None, take_none=True):
    """
    Returns js[key] if set, otherwise default. Note js[key] can be None.
    :param js:
    :param key:
    :param default:
    :param take_none:
    :return:
    """
    if js is None:
        return default
    if key not in js:
        return default
    if js[key] is None and not take_none:
        return default
    return js[key]


def drop_none(arr):
    """
    Drop none from the list
    :param arr:
    :return:
    """
    return [x for x in arr if x is not None]


def drop_empty(arr):
    """
    Drop empty array element
    :param arr:
    :return:
    """
    return [x for x in arr if not isinstance(x, list) or len(x) > 0]


def add_res(acc, elem):
    """
    Adds results to the accumulator
    :param acc:
    :param elem:
    :return:
    """
    if not isinstance(elem, list):
        elem = [elem]
    if acc is None:
        acc = []
    for x in elem:
        acc.append(x)
    return acc


def flatten(inp):
    """
    Flatten input array
    :param inp:
    :return:
    """
    if isinstance(inp, list):
        if len(inp) == 0:
            return []
        first, rest = inp[0], inp[1:]
        return flatten(first) + flatten(rest)
    else:
        return [inp]


def try_get_dn_part(subject, oid=None):
    """
    Tries to extracts the OID from the X500 name.
    :param subject:
    :param oid:
    :return:
    """
    try:
        if subject is None:
            return None
        if oid is None:
            return None

        for sub in subject:
            if oid is not None and sub.oid == oid:
                return sub.value
    except:
        pass
    return None


def try_get_dn_string(subject, shorten=False):
    """
    Returns DN as a string
    :param subject:
    :param shorten:
    :return:
    """
    from cryptography.x509.oid import NameOID
    oid_names = {
        NameOID.COMMON_NAME: "CN",
        NameOID.COUNTRY_NAME: "C",
        NameOID.LOCALITY_NAME: "L",
        NameOID.STATE_OR_PROVINCE_NAME: "ST",
        NameOID.STREET_ADDRESS: "St",
        NameOID.ORGANIZATION_NAME: "O",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        NameOID.SERIAL_NUMBER: "SN",
        NameOID.USER_ID: "userID",
        NameOID.DOMAIN_COMPONENT: "domainComponent",
        NameOID.EMAIL_ADDRESS: "emailAddress",
        NameOID.POSTAL_CODE: "ZIP",
    }

    ret = []
    try:
        for attribute in subject:
            oid = attribute.oid
            dot = oid.dotted_string
            oid_name = oid_names[oid] if shorten and oid in oid_names else oid._name
            val = attribute.value
            ret.append('%s: %s' % (oid_name, val))
    except:
        pass
    return ', '.join(ret)


def utf8ize(x):
    """
    Converts to utf8 if non-empty
    :param x:
    :return:
    """
    if x is None:
        return None
    return x.encode('utf-8')


def strip_spaces(x):
    """
    Strips spaces
    :param x:
    :return:
    """
    x = x.replace(' ', '')
    x = x.replace('\t', '')
    return x


def strip_pem(x):
    """
    Strips PEM to bare base64 encoded form
    :param x:
    :return:
    """
    if x is None:
        return None

    pem = x.replace('-----BEGIN CERTIFICATE-----', '')
    pem = pem.replace('-----END CERTIFICATE-----', '')
    pem = pem.replace(' ', '')
    pem = pem.replace('\t', '')
    pem = pem.replace('\r', '')
    pem = pem.replace('\n', '')
    return pem.strip()


def pem_to_der(x):
    """
    Converts PEM to DER
    :param x:
    :return:
    """
    if x is None:
        return None

    pem = strip_pem(x)
    return base64.b64decode(pem)


def unix_time(dt):
    if dt is None:
        return None
    cur = datetime.datetime.utcfromtimestamp(0)
    if dt.tzinfo is not None:
        cur.replace(tzinfo=dt.tzinfo)
    return (dt - cur).total_seconds()


class Tracelogger(object):
    """
    Prints traceback to the debugging logger if not shown before
    """

    def __init__(self, logger=None):
        self.logger = logger
        self._db = set()

    def log(self, cause=None, do_message=True, custom_msg=None):
        """
        Loads exception data from the current exception frame - should be called inside the except block
        :return:
        """
        message = error_message(self, cause=cause)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback_formatted = traceback.format_exc()
        traceback_val = traceback.extract_tb(exc_traceback)

        md5 = hashlib.md5(traceback_formatted.encode('utf-8')).hexdigest()

        if md5 in self._db:
            # self.logger.debug('Exception trace logged: %s' % md5)
            return

        if custom_msg is not None and cause is not None:
            self.logger.debug('%s : %s' % (custom_msg, cause))
        elif custom_msg is not None:
            self.logger.debug(custom_msg)
        elif cause is not None:
            self.logger.debug('%s' % cause)

        self.logger.debug(traceback_formatted)
        self._db.add(md5)


class AutoJSONEncoder(json.JSONEncoder):
    """
    JSON encoder trying to_json() first
    """
    def default(self, obj):
        try:
            return obj.to_json()
        except AttributeError:
            return self.default_classic(obj)

    def default_classic(self, o):
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

        if isinstance(o, set):
            return list(o)
        elif isinstance(o, RSAPublicNumbers):
            return {'n': o.n, 'e': o.e}
        else:
            return super(AutoJSONEncoder, self).default(o)


class TestResult(object):
    """
    Fingerprint test result
    """
    def __init__(self, data=None, **kwargs):
        self._data = collections.OrderedDict(data if data is not None else {})
        for key, value in iteritems(kwargs):
            self._data[key] = value

    @property
    def type(self):
        return defvalkey(self._data, 'type')

    @property
    def marked(self):
        return defvalkey(self._data, 'marked', False)

    @property
    def n(self):
        return defvalkey(self._data, 'n')

    @property
    def time_years(self):
        return defvalkey(self._data, 'time_years')

    @property
    def price_aws_c4(self):
        return defvalkey(self._data, 'price_aws_c4')

    def __getattr__(self, item):
        if item in self._data:
            return self._data[item]

        return None

    def to_json(self):
        self._data['marked'] = self.marked
        self._data['type'] = self.type
        return self._data


class ImportException(Exception):
    """Access to the resource was forbidden"""

    def __init__(self, message=None, cause=None):
        super(ImportException, self).__init__(message)


#
# Main fingerprinting tool
#

class RocaFingerprinter(object):
    """
    Key fingerprinter
    """

    def __init__(self):
        self.args = None
        self.trace_logger = Tracelogger(logger)
        self.jks_passwords = ['', 'changeit', 'chageit', 'root', 'server', 'test', 'alias', 'jks',
                              'tomcat', 'www', 'web', 'https']
        self.jks_file_passwords = None
        self.do_print = False

        self.tested = 0
        self.num_rsa = 0
        self.num_pem_certs = 0
        self.num_der_certs = 0
        self.num_rsa_keys = 0
        self.num_pgp_masters = 0
        self.num_pgp_total = 0
        self.num_ssh = 0
        self.num_json = 0
        self.num_apk = 0
        self.num_ldiff_cert = 0
        self.num_jks_cert = 0
        self.num_pkcs7_cert = 0
        self.found = 0

        self.primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
                       103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167]

        self.prints = [6, 30, 126, 1026, 5658, 107286, 199410, 8388606, 536870910, 2147483646, 67109890, 2199023255550,
                       8796093022206, 140737488355326, 5310023542746834, 576460752303423486, 1455791217086302986,
                       147573952589676412926, 20052041432995567486, 6041388139249378920330, 207530445072488465666,
                       9671406556917033397649406,
                       618970019642690137449562110,
                       79228162521181866724264247298,
                       2535301200456458802993406410750,
                       1760368345969468176824550810518,
                       50079290986288516948354744811034,
                       473022961816146413042658758988474,
                       10384593717069655257060992658440190,
                       144390480366845522447407333004847678774,
                       2722258935367507707706996859454145691646,
                       174224571863520493293247799005065324265470,
                       696898287454081973172991196020261297061886,
                       713623846352979940529142984724747568191373310,
                       1800793591454480341970779146165214289059119882,
                       126304807362733370595828809000324029340048915994,
                       11692013098647223345629478661730264157247460343806,
                       187072209578355573530071658587684226515959365500926]

        self.length_to_time_years = {
            512: 0.000220562038803,
            544: 0.00147111662211,
            576: 0.00673857391044,
            608: 0.0618100348655,
            640: 0.281991193891,
            672: 4.17998973277,
            704: 39.5102151646,
            736: 3473.56982013,
            768: 342674.912512,
            800: 89394704.8817,
            832: 8359663659.84,
            864: 44184838761000.0,
            896: -1,
            928: -1,
            960: -1,
            992: 0.0658249816453,
            1024: 0.266074841608,
            1056: 1.28258930217,
            1088: 7.38296771318,
            1120: 20.2173702373,
            1152: 58.9125352286,
            1184: 415.827799825,
            1216: 1536.17130832,
            1248: 5415.49876704,
            1280: 46281.7555548,
            1312: 208675.856834,
            1344: 1586124.1447,
            1376: 13481048.41,
            1408: 102251985.84,
            1440: 1520923586.93,
            1472: 30924687905.9,
            1504: 1933367534430.0,
            1536: 135663316837000.0,
            1568: 7582543380680000.0,
            1600: 5.1035570593e+17,
            1632: 3.8899705405e+19,
            1664: 3.66527648803e+21,
            1696: 3.77984169396e+23,
            1728: 5.14819714267e+25,
            1760: 6.24593092623e+27,
            1792: 8.73499845222e+29,
            1824: 1.87621309001e+32,
            1856: 2.9671795418e+34,
            1888: -1,
            1920: -1,
            1952: -1,
            1984: 28.6856385392,
            2016: 60.644701708,
            2048: 140.849490658,
            2080: 269.272545592,
            2112: 724.550220558,
            2144: 1262.66048991,
            2176: 3833.6903835,
            2208: 7049.61288162,
            2240: 14511.7355032,
            2272: 41968.716653,
            2304: 105863.580849,
            2336: 509819.310451,
            2368: 863135.14224,
            2400: 3730089.12073,
            2432: 14337269.1935,
            2464: 55914941.3902,
            2496: 144036102.003,
            2528: 972239354.935,
            2560: 1732510677.27,
            2592: 10345329708.8,
            2624: 72172778459.7,
            2656: 386464106155.0,
            2688: 1706310772440.0,
            2720: 14920435519400.0,
            2752: 77755063482200.0,
            2784: 1237655413740000.0,
            2816: 7524587305980000.0,
            2848: 4.66421299974e+16,
            2880: 5.41036780376e+17,
            2912: 6.07066413463e+18,
            2944: 6.17088797501e+19,
            2976: 4.35440413514e+20,
            3008: 1.04496910207e+22,
            3040: 2.91790333753e+23,
            3072: 2.84373206239e+25,
            3104: 1.21552661668e+27,
            3136: 1.14739892383e+29,
            3168: 7.03739127786e+30,
            3200: 5.5123347741e+32,
            3232: 5.46349546772e+34,
            3264: 3.07923071536e+36,
            3296: 4.88872482194e+37,
            3328: 4.74614877952e+39,
            3360: 5.94743522012e+41,
            3392: 3.63042884553e+43,
            3424: 3.15382165869e+45,
            3456: 4.22631927496e+47,
            3488: 4.57325850696e+50,
            3520: 7.58105156459e+52,
            3552: 8.44988925164e+54,
            3584: 2.1141023018e+57,
            3616: 2.95898599696e+59,
            3648: 7.23723533e+61,
            3680: 6.0951282339e+62,
            3712: 1.06824345519e+65,
            3744: 1.85662696289e+67,
            3776: 5.64628786015e+69,
            3808: 1.38273039654e+72,
            3840: -1,
            3872: -1,
            3904: -1,
            3936: -1,
            3968: 47950588.0004,
            4000: 134211454.052,
            4032: 201770331.337,
            4064: 613149724.539,
            4096: 1283252196.93,
        }

        # args init
        parser = self.init_parser()
        self.args = parser.parse_args(args=[])

    def has_fingerprint_real(self, modulus):
        """
        Returns true if the fingerprint was detected in the key
        :param modulus:
        :return:
        """
        self.tested += 1
        for i in range(0, len(self.primes)):
            if (1 << (modulus % self.primes[i])) & self.prints[i] == 0:
                return False

        self.found += 1
        return True

    def has_fingerprint_test(self, modulus):
        """
        Not sure :)
        :param modulus:
        :return:
        """
        return False

    has_fingerprint = has_fingerprint_real

    def mark_and_add_effort(self, modulus, json_info):
        """
        Inserts factorization effort for vulnerable modulus into json_info
        :param modulus:
        :param json_info:
        :return:
        """
        META_AMZ_FACT = 92. / 152.  # conversion from university cluster to AWS
        AMZ_C4_PRICE = 0.1  # price of 2 AWS CPUs per hour

        length = int(ceil(log(modulus, 2)))
        length_ceiling = int(ceil(length / 32)) * 32

        if length_ceiling in self.length_to_time_years:
            effort_time = self.length_to_time_years[length_ceiling]
        else:
            effort_time = -1
        if effort_time > 0:
            effort_time *= META_AMZ_FACT  # scaling to more powerful AWS CPU
            effort_price = effort_time * 365.25 * 24 * 0.5 * AMZ_C4_PRICE
        else:
            effort_price = -1
        json_info['marked'] = True
        json_info['time_years'] = effort_time
        json_info['price_aws_c4'] = effort_price
        return json_info

    def file_matches_extensions(self, fname, extensions):
        """
        True if file matches one of extensions
        :param fname:
        :param extensions:
        :return:
        """
        if not isinstance(extensions, types.ListType):
            extensions = [extensions]
        for ext in extensions:
            if fname.endswith('.%s' % ext):
                return True
        return False

    def process_inputs(self):
        """
        Processes input data
        :return:
        """
        ret = []
        files = self.args.files
        if files is None:
            return ret

        for fname in files:
            if fname == '-':
                if self.args.base64stdin:
                    for line in sys.stdin:
                        data = base64.b64decode(line)
                        ret.append(self.process_file(data, fname))

                    continue
                else:
                    fh = sys.stdin

            elif fname.endswith('.tar') or fname.endswith('.tar.gz'):
                sub = self.process_tar(fname)
                ret.append(sub)
                continue

            elif not os.path.isfile(fname):
                sub = self.process_dir(fname)
                ret.append(sub)
                continue

            else:
                fh = open(fname, 'rb')

            with fh:
                data = fh.read()
                sub = self.process_file(data, fname)
                ret.append(sub)

        return ret

    def process_tar(self, fname):
        """
        Tar(gz) archive processing
        :param fname:
        :return:
        """
        import tarfile  # lazy import, only when needed
        ret = []
        with tarfile.open(fname) as tr:
            members = tr.getmembers()
            for member in members:
                if not member.isfile():
                    continue
                fh = tr.extractfile(member)
                sub = self.process_file(fh.read(), member.name)
                ret.append(sub)
        return ret

    def process_dir(self, dirname):
        """
        Directory processing
        :param dirname:
        :return:
        """
        ret = []
        sub_rec = [f for f in os.listdir(dirname)]
        for fname in sub_rec:
            full_path = os.path.join(dirname, fname)

            if os.path.isfile(full_path):
                with open(full_path, 'rb') as fh:
                    sub = self.process_file(fh.read(), fname)
                    ret.append(sub)

            elif os.path.isdir(full_path):
                sub = self.process_dir(full_path)
                ret.append(sub)
        return ret

    def process_file(self, data, name):
        """
        Processes a single file
        :param data:
        :param name:
        :return:
        """
        try:
            return self.process_file_autodetect(data, name)

        except Exception as e:
            logger.debug('Excetion processing file %s : %s' % (name, e))
            self.trace_logger.log(e)

        # autodetection fallback - all formats
        ret = []
        logger.debug('processing %s as PEM' % name)
        ret.append(self.process_pem(data, name))

        logger.debug('processing %s as DER' % name)
        ret.append(self.process_der(data, name))

        logger.debug('processing %s as PGP' % name)
        ret.append(self.process_pgp(data, name))

        logger.debug('processing %s as SSH' % name)
        ret.append(self.process_ssh(data, name))

        logger.debug('processing %s as JSON' % name)
        ret.append(self.process_json(data, name))

        logger.debug('processing %s as APK' % name)
        ret.append(self.process_apk(data, name))

        logger.debug('processing %s as MOD' % name)
        ret.append(self.process_mod(data, name))

        logger.debug('processing %s as LDIFF' % name)
        ret.append(self.process_ldiff(data, name))

        logger.debug('processing %s as JKS' % name)
        ret.append(self.process_jks(data, name))

        logger.debug('processing %s as PKCS7' % name)
        ret.append(self.process_pkcs7(data, name))
        return ret

    def process_file_autodetect(self, data, name):
        """
        Processes a single file - format autodetection
        :param data:
        :param name:
        :return:
        """
        is_ssh_file = data.startswith('ssh-rsa') or 'ssh-rsa ' in data
        is_pgp_file = data.startswith('-----BEGIN PGP')
        is_pkcs7_file = data.startswith('-----BEGIN PKCS7')
        is_pem_file = data.startswith('-----BEGIN') and not is_pgp_file
        is_ldiff_file = 'binary::' in data

        is_pgp = is_pgp_file or (self.file_matches_extensions(name, ['pgp', 'gpg', 'key', 'pub', 'asc'])
                                 and not is_ssh_file
                                 and not is_pem_file)
        is_pgp |= self.args.file_pgp

        is_crt_ext = self.file_matches_extensions(name, ['der', 'crt', 'cer', 'cert', 'x509', 'key', 'pub', 'ca'])

        is_pem = self.file_matches_extensions(name, 'pem') or is_pem_file
        is_pem |= self.args.file_pem

        is_der = not is_pem and not is_ssh_file and not is_pgp_file and is_crt_ext
        is_der |= self.args.file_der

        is_ssh = self.file_matches_extensions(name, ['ssh', 'pub']) or is_ssh_file
        is_ssh |= self.args.file_ssh

        is_apk = self.file_matches_extensions(name, 'apk')

        is_mod = self.file_matches_extensions(name, ['txt', 'mod', 'mods', 'moduli'])
        is_mod |= not is_pem and not is_der and not is_pgp and not is_ssh_file and not is_apk
        is_mod |= self.args.file_mod

        is_json = self.file_matches_extensions(name, ['json', 'js']) or data.startswith('{') or data.startswith('[')
        is_json |= self.args.file_json

        is_ldiff = self.file_matches_extensions(name, ['ldiff', 'ldap']) or is_ldiff_file
        is_ldiff |= self.args.file_ldiff

        is_jks = self.file_matches_extensions(name, ['jks', 'bks'])
        is_pkcs7 = self.file_matches_extensions(name, ['pkcs7', 'p7s', 'p7'])
        is_pkcs7 |= is_pkcs7_file
        is_pkcs7 |= self.args.file_pkcs7

        det = is_pem or is_der or is_pgp or is_ssh or is_mod or is_json or is_apk or is_ldiff or is_jks
        ret = []
        if is_pem:
            logger.debug('processing %s as PEM' % name)
            ret.append(self.process_pem(data, name))

        if is_der:
            logger.debug('processing %s as DER' % name)
            ret.append(self.process_der(data, name))

        if is_pgp:
            logger.debug('processing %s as PGP' % name)
            ret.append(self.process_pgp(data, name))

        if is_ssh:
            logger.debug('processing %s as SSH' % name)
            ret.append(self.process_ssh(data, name))

        if is_json:
            logger.debug('processing %s as JSON' % name)
            ret.append(self.process_json(data, name))

        if is_apk:
            logger.debug('processing %s as APK' % name)
            ret.append(self.process_apk(data, name))

        if is_mod:
            logger.debug('processing %s as MOD' % name)
            ret.append(self.process_mod(data, name))

        if is_ldiff:
            logger.debug('processing %s as LDIFF' % name)
            ret.append(self.process_ldiff(data, name))

        if is_jks:
            logger.debug('processing %s as JKS' % name)
            ret.append(self.process_jks(data, name))

        if is_pkcs7:
            logger.debug('processing %s as PKCS7' % name)
            ret.append(self.process_pkcs7(data, name))

        if not det:
            logger.debug('Undetected (skipped) file: %s' % name)
        return ret

    def process_pem(self, data, name):
        """
        PEM processing - splitting further by the type of the records
        :param data:
        :param name:
        :return:
        """
        try:
            parts = re.split(r'-{5,}BEGIN', data)
            if len(parts) == 0:
                return None

            if len(parts[0]) == 0:
                parts.pop(0)

            crt_arr = ['-----BEGIN' + x for x in parts]
            for idx, pem_rec in enumerate(crt_arr):
                pem_rec = pem_rec.strip()
                if len(pem_rec) == 0:
                    continue

                if pem_rec.startswith('-----BEGIN CERTIF'):
                    return self.process_pem_cert(pem_rec, name, idx)
                elif pem_rec.startswith('-----BEGIN '):  # fallback
                    return self.process_pem_rsakey(pem_rec, name, idx)

        except Exception as e:
            logger.debug('Exception processing PEM file %s : %s' % (name, e))
            self.trace_logger.log(e)
        return None

    def process_pem_cert(self, data, name, idx):
        """
        Processes PEM encoded certificate
        :param data:
        :param name:
        :param idx:
        :return:
        """
        from cryptography.x509.base import load_der_x509_certificate
        try:
            x509 = load_der_x509_certificate(pem_to_der(data), self.get_backend())
            self.num_pem_certs += 1
            return self.process_x509(x509, name=name, idx=idx, data=data, pem=True, source='pem-cert')

        except Exception as e:
            logger.debug('PEM processing failed: %s' % e)
            self.trace_logger.log(e)

    def process_pem_rsakey(self, data, name, idx):
        """
        Processes PEM encoded RSA key
        :param data:
        :param name:
        :param idx:
        :return:
        """
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        try:
	    if data.startswith('-----BEGIN RSA PUBLIC KEY'):
                rsa = load_pem_public_key(data, self.get_backend())
                public_numbers = rsa.public_numbers()
	    elif data.startswith('-----BEGIN PUBLIC KEY'):
                rsa = load_pem_public_key(data, self.get_backend())
                public_numbers = rsa.public_numbers()
	    elif data.startswith('-----BEGIN RSA PRIVATE KEY'):
                rsa = load_pem_private_key(data, None, self.get_backend())
                public_numbers = rsa.private_numbers().public_numbers
	    elif data.startswith('-----BEGIN PRIVATE KEY'):
                rsa = load_pem_private_key(data, None, self.get_backend())
                public_numbers = rsa.private_numbers().public_numbers
	    else:
	        raise TypeError
            self.num_rsa_keys += 1
            self.num_rsa += 1

            js = collections.OrderedDict()
            js['type'] = 'pem-rsa-key'
            js['fname'] = name
            js['idx'] = idx
            js['pem'] = data
            js['e'] = '0x%x' % public_numbers.e
            js['n'] = '0x%x' % public_numbers.n

            if self.has_fingerprint(public_numbers.n):
                logger.warning('Fingerprint found in PEM RSA key %s ' % name)
                self.mark_and_add_effort(public_numbers.n, js)

                if self.do_print:
                    print(json.dumps(js))

            return TestResult(js)

        except Exception as e:
            logger.debug('Pubkey loading error: %s : %s [%s] : %s' % (name, idx, data[:20], e))
            self.trace_logger.log(e)

    def process_der(self, data, name):
        """
        DER processing
        :param data:
        :param name:
        :return:
        """
        from cryptography.x509.base import load_der_x509_certificate
        try:
            x509 = load_der_x509_certificate(data, self.get_backend())
            self.num_der_certs += 1
            return self.process_x509(x509, name=name, pem=False, source='der-cert')

        except Exception as e:
            logger.debug('DER processing failed: %s : %s' % (name, e))
            self.trace_logger.log(e)

    def process_x509(self, x509, name, idx=None, data=None, pem=True, source='', aux=None):
        """
        Processing parsed X509 certificate
        :param x509:
        :param name:
        :param idx:
        :param data:
        :param pem:
        :param source:
        :param aux:
        :return:
        """
        if x509 is None:
            return

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        from cryptography.x509.oid import NameOID

        pub = x509.public_key()
        if not isinstance(pub, RSAPublicKey):
            return

        self.num_rsa += 1
        pubnum = x509.public_key().public_numbers()

        js = collections.OrderedDict()
        js['type'] = source
        js['fname'] = name
        js['idx'] = idx
        js['fprint'] = binascii.hexlify(x509.fingerprint(hashes.SHA256()))
        js['subject'] = utf8ize(try_get_dn_string(x509.subject, shorten=True))
        js['issuer'] = utf8ize(try_get_dn_string(x509.issuer, shorten=True))
        js['issuer_org'] = utf8ize(try_get_dn_part(x509.issuer, NameOID.ORGANIZATION_NAME))
        js['created_at'] = self.strtime(x509.not_valid_before)
        js['created_at_utc'] = unix_time(x509.not_valid_before)
        js['not_valid_after_utc'] = unix_time(x509.not_valid_after)
        js['pem'] = data if pem else None
        js['aux'] = aux
        js['e'] = '0x%x' % pubnum.e
        js['n'] = '0x%x' % pubnum.n

        if self.has_fingerprint(pubnum.n):
            logger.warning('Fingerprint found in the Certificate %s idx %s ' % (name, idx))
            self.mark_and_add_effort(pubnum.n, js)

            if self.do_print:
                print(json.dumps(js))

        return TestResult(js)

    def process_pgp(self, data, name):
        """
        PGP key processing
        :param data:
        :param name:
        :return:
        """
        ret = []
        try:
            parts = re.split(r'-{5,}BEGIN', data)
            if len(parts) == 0:
                return

            if len(parts[0]) == 0:
                parts.pop(0)

            crt_arr = ['-----BEGIN' + x for x in parts]
            for idx, pem_rec in enumerate(crt_arr):
                try:
                    pem_rec = pem_rec.strip()
                    if len(pem_rec) == 0:
                        continue

                    ret.append(self.process_pgp_raw(pem_rec, name, idx))

                except Exception as e:
                    logger.error('Exception in processing PGP rec file %s: %s' % (name, e))
                    self.trace_logger.log(e)

        except Exception as e:
            logger.error('Exception in processing PGP file %s: %s' % (name, e))
            self.trace_logger.log(e)
        return ret

    def process_pgp_raw(self, data, name, file_idx=None):
        """
        Processes single PGP key
        :param data: file data
        :param name: file name
        :param file_idx: index in the file
        :return:
        """
        try:
            from pgpdump.data import AsciiData
            from pgpdump.packet import SignaturePacket, PublicKeyPacket, PublicSubkeyPacket, UserIDPacket

        except Exception as e:
            logger.warning('Could not import pgpdump, try running: pip install pgpdump')
            return [TestResult(fname=name, type='pgp', error='cannot-import')]

        ret = []
        js_base = collections.OrderedDict()

        pgp_key_data = AsciiData(data)
        packets = list(pgp_key_data.packets())
        self.num_pgp_masters += 1

        master_fprint = None
        master_key_id = None
        identities = []
        pubkeys = []
        sign_key_ids = []
        sig_cnt = 0
        for idx, packet in enumerate(packets):
            if isinstance(packet, PublicKeyPacket):
                master_fprint = packet.fingerprint
                master_key_id = format_pgp_key(packet.key_id)
                pubkeys.append(packet)
            elif isinstance(packet, PublicSubkeyPacket):
                pubkeys.append(packet)
            elif isinstance(packet, UserIDPacket):
                identities.append(packet)
            elif isinstance(packet, SignaturePacket):
                sign_key_ids.append(packet.key_id)
                sig_cnt += 1

        # Names / identities
        ids_arr = []
        identity = None
        for packet in identities:
            idjs = collections.OrderedDict()
            idjs['name'] = packet.user_name
            idjs['email'] = packet.user_email
            ids_arr.append(idjs)

            if identity is None:
                identity = '%s <%s>' % (packet.user_name, packet.user_email)

        js_base['type'] = 'pgp'
        js_base['fname'] = name
        js_base['fname_idx'] = file_idx
        js_base['master_key_id'] = master_key_id
        js_base['master_fprint'] = master_fprint
        js_base['identities'] = ids_arr
        js_base['signatures_count'] = sig_cnt
        js_base['packets_count'] = len(packets)
        js_base['keys_count'] = len(pubkeys)
        js_base['signature_keys'] = list(set(sign_key_ids))

        # Public keys processing
        for packet in pubkeys:
            try:
                self.num_pgp_total += 1
                if packet.modulus is None:
                    continue

                self.num_rsa += 1
                js = collections.OrderedDict(js_base)
                js['created_at'] = self.strtime(packet.creation_time)
                js['created_at_utc'] = unix_time(packet.creation_time)
                js['is_master'] = master_fprint == packet.fingerprint
                js['kid'] = format_pgp_key(packet.key_id)
                js['bitsize'] = packet.modulus_bitlen
                js['master_kid'] = master_key_id
                js['e'] = '0x%x' % packet.exponent
                js['n'] = '0x%x' % packet.modulus

                if self.has_fingerprint(packet.modulus):
                    self.mark_and_add_effort(packet.modulus, js)
                    logger.warning('Fingerprint found in PGP key %s key ID 0x%s' % (name, js['kid']))

                    if self.do_print:
                        print(json.dumps(js))

                ret.append(TestResult(js))

            except Exception as e:
                logger.error('Excetion in processing the key: %s' % e)
                self.trace_logger.log(e)
        return ret

    def process_ssh(self, data, name):
        """
        Processes SSH keys
        :param data:
        :param name:
        :return:
        """
        if data is None or len(data) == 0:
            return

        ret = []
        try:
            lines = [x.strip() for x in data.split('\n')]
            for idx, line in enumerate(lines):
                ret.append(self.process_ssh_line(line, name, idx))

        except Exception as e:
            logger.debug('Exception in processing SSH public key %s : %s' % (name, e))
            self.trace_logger.log(e)
        return ret

    def process_ssh_line(self, data, name, idx):
        """
        Processes single SSH key
        :param data:
        :param name:
        :param idx:
        :return:
        """
        data = data.strip()
        if 'ssh-rsa' not in data:
            return

        # strip ssh params / adjustments
        try:
            data = data[data.find('ssh-rsa'):]
        except:
            pass

        from cryptography.hazmat.primitives.serialization import load_ssh_public_key
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        try:
            key_obj = load_ssh_public_key(data, self.get_backend())
            self.num_ssh += 1

            if not isinstance(key_obj, RSAPublicKey):
                return

            self.num_rsa += 1
            numbers = key_obj.public_numbers()

            js = collections.OrderedDict()
            js['type'] = 'ssh-rsa'
            js['fname'] = name
            js['idx'] = idx
            js['e'] = '0x%x' % numbers.e
            js['n'] = '0x%x' % numbers.n
            js['ssh'] = data

            if self.has_fingerprint(numbers.n):
                logger.warning('Fingerprint found in the SSH key %s idx %s ' % (name, idx))
                self.mark_and_add_effort(numbers.n, js)

                if self.do_print:
                    print(json.dumps(js))

            return TestResult(js)

        except Exception as e:
            logger.debug('Exception in processing SSH public key %s idx %s : %s' % (name, idx, e))
            self.trace_logger.log(e)

    def process_json(self, data, name):
        """
        Processes as a JSON
        :param data:
        :param name:
        :return:
        """
        if data is None or len(data) == 0:
            return

        ret = []
        try:
            lines = [x.strip() for x in data.split('\n')]
            for idx, line in enumerate(lines):
                ret.append(self.process_json_line(line, name, idx))

        except Exception as e:
            logger.debug('Exception in processing JSON %s : %s' % (name, e))
            self.trace_logger.log(e)
        return ret

    def process_json_line(self, data, name, idx):
        """
        Processes single json line
        :param data:
        :param name:
        :param idx:
        :return:
        """
        data = data.strip()
        if len(data) == 0:
            return

        ret = []
        try:
            js = json.loads(data)
            self.num_json += 1
            ret.append(self.process_json_rec(js, name, idx, []))

        except Exception as e:
            logger.debug('Exception in processing JSON %s idx %s : %s' % (name, idx, e))
            self.trace_logger.log(e)
        return ret

    def process_json_rec(self, data, name, idx, sub_idx):
        """
        Processes json rec - json object
        :param data:
        :param name:
        :param idx:
        :param sub_idx:
        :return:
        """
        ret = []
        if isinstance(data, types.ListType):
            for kidx, rec in enumerate(data):
                sub = self.process_json_rec(rec, name, idx, list(sub_idx + [kidx]))
                ret.append(sub)
            return ret

        if isinstance(data, types.DictionaryType):
            for key in data:
                rec = data[key]
                sub = self.process_json_rec(rec, name, idx, list(sub_idx + [rec]))
                ret.append(sub)

            if 'n' in data:
                ret.append(self.process_js_mod(data['n'], name, idx, sub_idx))
            if 'mod' in data:
                ret.append(self.process_js_mod(data['mod'], name, idx, sub_idx))
            if 'cert' in data:
                ret.append(self.process_js_certs([data['cert']], name, idx, sub_idx))
            if 'certs' in data:
                ret.append(self.process_js_certs(data['certs'], name, idx, sub_idx))
        return ret

    def process_js_mod(self, data, name, idx, sub_idx):
        """
        Processes one moduli from JSON
        :param data:
        :param name:
        :param idx:
        :param sub_idx:
        :return:
        """
        if isinstance(data, types.IntType):
            js = collections.OrderedDict()
            js['type'] = 'js-mod-num'
            js['fname'] = name
            js['idx'] = idx
            js['sub_idx'] = sub_idx
            js['n'] = '0x%x' % data

            if self.has_fingerprint(data):
                logger.warning('Fingerprint found in json int modulus %s idx %s %s' % (name, idx, sub_idx))
                self.mark_and_add_effort(data, js)

                if self.do_print:
                    print(json.dumps(js))

            return TestResult(js)

        self.process_mod_line(data, name, idx, aux={'stype': 'json', 'sub_idx': sub_idx})

    def process_js_certs(self, data, name, idx, sub_idx):
        """
        Process one certificate from JSON
        :param data:
        :param name:
        :param idx:
        :param sub_idx:
        :return:
        """
        from cryptography.x509.base import load_der_x509_certificate

        ret = []
        for crt_hex in data:
            try:
                bindata = base64.b64decode(crt_hex)
                x509 = load_der_x509_certificate(bindata, self.get_backend())

                self.num_ldiff_cert += 1
                sub = self.process_x509(x509, name=name, pem=False, source='ldiff-cert')
                ret.append(sub)

            except Exception as e:
                logger.debug('Error in line JSON cert file processing %s, idx %s, subidx %s : %s'
                             % (name, idx, sub_idx, e))
                self.trace_logger.log(e)
        return ret

    def process_apk(self, data, name):
        """
        Processes Android application
        :param data:
        :param name:
        :return:
        """
        try:
            from apk_parse.apk import APK
        except Exception as e:
            logger.warning('Could not import apk_parse, try running: pip install apk_parse_ph4')
            return [TestResult(fname=name, type='apk-pem-cert', error='cannot-import')]

        ret = []
        try:
            from cryptography.x509.base import load_der_x509_certificate
            apkf = APK(data, process_now=False, process_file_types=False, raw=True,
                       temp_dir=self.args.tmp_dir)
            apkf.process()
            self.num_apk += 1

            pem = apkf.cert_pem
            aux = {'subtype': 'apk'}

            x509 = load_der_x509_certificate(pem_to_der(pem), self.get_backend())

            sub = self.process_x509(x509, name=name, idx=0, data=data, pem=True, source='apk-pem-cert', aux=aux)
            ret.append(sub)

        except Exception as e:
            logger.debug('Exception in processing APK %s : %s' % (name, e))
            self.trace_logger.log(e)
        return ret

    def process_mod(self, data, name):
        """
        Processing one modulus per line
        :param data:
        :param name:
        :return:
        """
        ret = []
        try:
            lines = [x.strip() for x in data.split('\n')]
            for idx, line in enumerate(lines):
                sub = self.process_mod_line(line, name, idx)
                ret.append(sub)

        except Exception as e:
            logger.debug('Error in line mod file processing %s : %s' % (name, e))
            self.trace_logger.log(e)
        return ret

    def process_mod_line(self, data, name, idx, aux=None):
        """
        Processes one line mod
        :param data:
        :param name:
        :param idx:
        :param aux:
        :return:
        """
        if data is None or len(data) == 0:
            return

        ret = []
        try:
            if self.args.key_fmt_base64 or re.match(r'^[a-zA-Z0-9+/=\s\t]+$', data):
                ret.append(self.process_mod_line_num(strip_spaces(data), name, idx, 'base64', aux))

            if self.args.key_fmt_hex or re.match(r'^(0x)?[a-fA-F0-9\s\t]+$', data):
                ret.append(self.process_mod_line_num(strip_spaces(data), name, idx, 'hex', aux))

            if self.args.key_fmt_dec or re.match(r'^[0-9\s\t]+$', data):
                ret.append(self.process_mod_line_num(strip_spaces(data), name, idx, 'dec', aux))

        except Exception as e:
            logger.debug('Error in line mod processing %s idx %s : %s' % (name, idx, e))
            self.trace_logger.log(e)
        return ret

    def process_mod_line_num(self, data, name, idx, num_type='hex', aux=None):
        """
        Processes particular number
        :param data:
        :param name:
        :param idx:
        :param num_type:
        :param aux:
        :return:
        """
        try:
            num = 0
            if num_type == 'base64':
                num = int(base64.b16encode(base64.b64decode(data)), 16)
            elif num_type == 'hex':
                num = int(strip_hex_prefix(data), 16)
            elif num_type == 'dec':
                num = int(data)
            else:
                raise ValueError('Unknown number format: %s' % num_type)

            js = collections.OrderedDict()
            js['type'] = 'mod-%s' % num_type
            js['fname'] = name
            js['idx'] = idx
            js['aux'] = aux
            js['n'] = '0x%x' % num

            if self.has_fingerprint(num):
                logger.warning('Fingerprint found in modulus %s idx %s ' % (name, idx))
                self.mark_and_add_effort(num, js)

                if self.do_print:
                    print(json.dumps(js))
            return TestResult(js)

        except Exception as e:
            logger.debug('Exception in testing modulus %s idx %s : %s data: %s' % (name, idx, e, data[:30]))
            self.trace_logger.log(e)

    def process_ldiff(self, data, name):
        """
        Processes LDAP output
        field;binary::blob
        :param data:
        :param name:
        :return:
        """
        from cryptography.x509.base import load_der_x509_certificate
        reg = re.compile(r'binary::\s*([0-9a-zA-Z+/=\s\t\r\n]{20,})$', re.MULTILINE | re.DOTALL)
        matches = re.findall(reg, str(data))

        ret = []
        num_certs_found = 0
        for idx, match in enumerate(matches):
            match = re.sub('[\r\t\n\s]', '', match)
            try:
                bindata = base64.b64decode(match)
                x509 = load_der_x509_certificate(bindata, self.get_backend())

                self.num_ldiff_cert += 1
                sub = self.process_x509(x509, name=name, pem=False, source='ldiff-cert')
                ret.append(sub)

            except Exception as e:
                logger.debug('Error in line ldiff file processing %s, idx %s, matchlen %s : %s'
                             % (name, idx, len(match), e))
                self.trace_logger.log(e)
        return ret

    def process_jks(self, data, name):
        """
        Processes Java Key Store file
        :param data:
        :param name:
        :return:
        """
        if self.jks_file_passwords is None and self.args.jks_pass_file is not None:
            self.jks_file_passwords = []
            if not os.path.exists(self.args.jks_pass_file):
                logger.warning('JKS password file %s does not exist' % self.args.jks_pass_file)
            with open(self.args.jks_pass_file) as fh:
                self.jks_file_passwords = sorted(list(set([x.strip() for x in fh])))

        try:
            ks = self.try_open_jks(data, name)
            if ks is None:
                logger.warning('Could not open JKS file: %s, password not valid, '
                               'try specify passwords in --jks-pass-file' % name)
                return

            # certs
            from cryptography.x509.base import load_der_x509_certificate

            ret = []
            for alias, cert in ks.certs.items():
                try:
                    x509 = load_der_x509_certificate(cert.cert, self.get_backend())

                    self.num_jks_cert += 1
                    sub = self.process_x509(x509, name=name, pem=False, source='jks-cert', aux='cert-%s' % alias)
                    ret.append(sub)

                except Exception as e:
                    logger.debug('Error in JKS cert processing %s, alias %s : %s' % (name, alias, e))
                    self.trace_logger.log(e)

            # priv key chains
            for alias, pk in ks.private_keys.items():
                for idx, cert in enumerate(pk.cert_chain):
                    try:
                        x509 = load_der_x509_certificate(cert[1], self.get_backend())

                        self.num_jks_cert += 1
                        sub = self.process_x509(x509, name=name, pem=False, source='jks-cert-chain',
                                                aux='cert-chain-%s-%s' % (alias, idx))
                        ret.append(sub)

                    except Exception as e:
                        logger.debug('Error in JKS priv key cert-chain processing %s, alias %s %s : %s'
                                     % (name, alias, idx, e))
                        self.trace_logger.log(e)
            return ret

        except ImportException:
            return [TestResult(fname=name, type='jks-cert', error='cannot-import')]

        except Exception as e:
            logger.warning('Exception in JKS processing: %s' % e)
            return None

    def try_open_jks(self, data, name):
        """
        Tries to guess JKS password
        :param name:
        :param data:
        :return:
        """
        try:
            import jks
        except:
            logger.warning('Could not import jks, try running: pip install pyjks')
            raise ImportException('Cannot import pyjks')

        pwdlist = sorted(list(set(self.jks_file_passwords + self.jks_passwords)))
        for cur in pwdlist:
            try:
                return jks.KeyStore.loads(data, cur)
            except Exception as e:
                pass
        return None

    def process_pkcs7(self, data, name):
        """
        Process PKCS7 signature with certificate in it.
        :param data:
        :param name:
        :return:
        """
        from cryptography.hazmat.backends.openssl.backend import backend
        from cryptography.hazmat.backends.openssl.x509 import _Certificate

        # DER conversion
        is_pem = data.startswith('-----')
        if re.match(r'^[a-zA-Z0-9-\s+=/]+$', data):
            is_pem = True

        try:
            der = data
            if is_pem:
                data = re.sub(r'\s*-----\s*BEGIN\s+PKCS7\s*-----', '', data)
                data = re.sub(r'\s*-----\s*END\s+PKCS7\s*-----', '', data)
                der = base64.b64decode(data)

            bio = backend._bytes_to_bio(der)
            pkcs7 = backend._lib.d2i_PKCS7_bio(bio.bio, backend._ffi.NULL)
            backend.openssl_assert(pkcs7 != backend._ffi.NULL)
            signers = backend._lib.PKCS7_get0_signers(pkcs7, backend._ffi.NULL, 0)
            backend.openssl_assert(signers != backend._ffi.NULL)
            backend.openssl_assert(backend._lib.sk_X509_num(signers) > 0)
            x509_ptr = backend._lib.sk_X509_value(signers, 0)
            backend.openssl_assert(x509_ptr != backend._ffi.NULL)
            x509_ptr = backend._ffi.gc(x509_ptr, backend._lib.X509_free)
            x509 = _Certificate(backend, x509_ptr)

            self.num_pkcs7_cert += 1

            return [self.process_x509(x509, name=name, pem=False, source='pkcs7-cert', aux='')]

        except Exception as e:
            logger.debug('Error in PKCS7 processing %s: %s' % (name, e))
            self.trace_logger.log(e)

    #
    # Helpers & worker
    #

    def strtime(self, x):
        """
        Simple time format
        :param x:
        :return:
        """
        if x is None:
            return x
        return x.strftime('%Y-%m-%d')

    def get_backend(self, backend=None):
        """
        Default crypto backend
        :param backend:
        :return:
        """
        from cryptography.hazmat.backends import default_backend
        return default_backend() if backend is None else backend

    def dump(self, ret):
        """
        Dumps the return value
        :param ret:
        :return:
        """
        if self.args.flatten:
            ret = drop_none(flatten(ret))

        logger.info('Dump: \n' + json.dumps(ret, cls=AutoJSONEncoder, indent=2 if self.args.indent else None))

    def work(self):
        """
        Entry point after argument processing.
        :return:
        """
        self.do_print = True
        ret = self.process_inputs()

        if self.args.dump:
            self.dump(ret)

        logger.info('### SUMMARY ####################')
        logger.info('Records tested: %s' % self.tested)
        logger.info('.. PEM certs: . . . %s' % self.num_pem_certs)
        logger.info('.. DER certs: . . . %s' % self.num_der_certs)
        logger.info('.. RSA key files: . %s' % self.num_rsa_keys)
        logger.info('.. PGP master keys: %s' % self.num_pgp_masters)
        logger.info('.. PGP total keys:  %s' % self.num_pgp_total)
        logger.info('.. SSH keys:  . . . %s' % self.num_ssh)
        logger.info('.. APK keys:  . . . %s' % self.num_apk)
        logger.info('.. JSON keys: . . . %s' % self.num_json)
        logger.info('.. LDIFF certs: . . %s' % self.num_ldiff_cert)
        logger.info('.. JKS certs: . . . %s' % self.num_jks_cert)
        logger.info('.. PKCS7: . . . . . %s' % self.num_pkcs7_cert)
        logger.debug('. Total RSA keys . %s  (# of keys RSA extracted & analyzed)' % self.num_rsa)
        if self.found > 0:
            logger.info('Fingerprinted keys found: %s' % self.found)
            logger.info('WARNING: Potential vulnerability')
        else:
            logger.info('No fingerprinted keys found (OK)')
        logger.info('################################')

    def init_parser(self):
        """
        Init command line parser
        :return:
        """
        parser = argparse.ArgumentParser(description='ROCA Fingerprinter')

        parser.add_argument('--tmp', dest='tmp_dir', default='.',
                            help='Temporary dir for subprocessing (e.g. APK parsing scratch)')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--dump', dest='dump', default=False, action='store_const', const=True,
                            help='Dump all processed info')

        parser.add_argument('--flatten', dest='flatten', default=False, action='store_const', const=True,
                            help='Flatten the dump')

        parser.add_argument('--indent', dest='indent', default=False, action='store_const', const=True,
                            help='Indent the dump')

        parser.add_argument('--base64-stdin', dest='base64stdin', default=False, action='store_const', const=True,
                            help='Decode STDIN as base64')

        parser.add_argument('--file-pem', dest='file_pem', default=False, action='store_const', const=True,
                            help='Force read as PEM encoded file')

        parser.add_argument('--file-der', dest='file_der', default=False, action='store_const', const=True,
                            help='Force read as DER encoded file')

        parser.add_argument('--file-pgp', dest='file_pgp', default=False, action='store_const', const=True,
                            help='Force read as PGP ASC encoded file')

        parser.add_argument('--file-ssh', dest='file_ssh', default=False, action='store_const', const=True,
                            help='Force read as SSH public key file')

        parser.add_argument('--file-mod', dest='file_mod', default=False, action='store_const', const=True,
                            help='Force read as One modulus per line')

        parser.add_argument('--file-json', dest='file_json', default=False, action='store_const', const=True,
                            help='Force read as JSON file')

        parser.add_argument('--file-ldiff', dest='file_ldiff', default=False, action='store_const', const=True,
                            help='Force read as LDIFF file')

        parser.add_argument('--file-pkcs7', dest='file_pkcs7', default=False, action='store_const', const=True,
                            help='Force read as PKCS7 file')

        parser.add_argument('--key-fmt-base64', dest='key_fmt_base64', default=False, action='store_const', const=True,
                            help='Modulus per line, base64 encoded')

        parser.add_argument('--key-fmt-hex', dest='key_fmt_hex', default=False, action='store_const', const=True,
                            help='Modulus per line, hex encoded')

        parser.add_argument('--key-fmt-dec', dest='key_fmt_dec', default=False, action='store_const', const=True,
                            help='Modulus per line, dec encoded')

        parser.add_argument('--jks-pass-file', dest='jks_pass_file', default=None,
                            help='Password file for JKS, one per line')

        parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='files to process')
        return parser

    def main(self):
        """
        Main entry point
        :return:
        """
        parser = self.init_parser()
        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG, fmt=LOG_FORMAT)

        self.work()


def main():
    app = RocaFingerprinter()
    app.main()


if __name__ == '__main__':
    main()

