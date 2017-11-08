#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
TLS fingerprinting

Reads from one or more text files that contain a newline-separated list of
address:port entries. Example:

    github.com:443
    google.com:443
    internal.example.com:8080


Script requirements:

    - See detect.py requirements

"""

import sys
import argparse
import logging
import coloredlogs
from ssl import get_server_certificate
from roca.detect import RocaFingerprinter


logger = logging.getLogger(__name__)


#
# Main class
#

class RocaTLSFingerprinter(object):
    """
    TLS fingerprinter
    """

    def __init__(self):
        self.args = None
        self.roca = RocaFingerprinter()

    def process_tls(self, data, name):
        """
        Remote TLS processing - one address:port per line
        :param data:
        :param name:
        :return:
        """
        ret = []
        try:
            lines = [x.strip() for x in data.split('\n')]
            for idx, line in enumerate(lines):
                if line == '':
                    continue

                sub = self.process_host(line, name, idx)
                if sub is not None:
                    ret.append(sub)

        except Exception as e:
            logger.error('Error in file processing %s : %s' % (name, e))
            self.roca.trace_logger.log(e)
        return ret

    def process_host(self, host_spec, name, line_idx=0):
        """
        One host spec processing
        :param host_spec:
        :param name:
        :param line_idx:
        :return:
        """
        try:
            parts = host_spec.split(':', 1)
            host = parts[0].strip()
            port = parts[1] if len(parts) > 1 else 443
            pem_cert = self.get_server_certificate(host, port)
            if pem_cert:
                sub = self.roca.process_pem_cert(pem_cert, name, line_idx)
                return sub

        except Exception as e:
            logger.error('Error in file processing %s (%s) : %s' % (host_spec, name, e))
            self.roca.trace_logger.log(e)

    def get_server_certificate(self, host, port):
        """
        Gets the remote x.509 certificate
        :param host:
        :param port:
        :return:
        """
        logger.info("Fetching server certificate from %s:%s" % (host,port))
        try:
            return get_server_certificate((host, int(port)))
        except Exception as e:
            logger.error('Error getting server certificate from %s:%s: %s' %
                         (host, port, e))
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

            # arguments are host specs
            if self.args.hosts:
                sub = self.process_host(fname, fname, 0)
                if sub is not None:
                    ret.append(sub)
                continue

            # arguments are file names
            fh = open(fname, 'r')
            with fh:
                data = fh.read()
                sub = self.process_tls(data, fname)
                ret.append(sub)

        return ret

    def work(self):
        """
        Entry point after argument processing.
        :return:
        """
        self.roca.do_print = True
        ret = self.process_inputs()

        if self.args.dump:
            self.roca.dump(ret)

        if self.roca.found > 0:
            logger.info('Fingerprinted keys found: %s' % self.roca.found)
            logger.info('WARNING: Potential vulnerability')
        else:
            logger.info('No fingerprinted keys found (OK)')

    def init_parser(self):
        """
        Init command line parser
        :return:
        """
        parser = argparse.ArgumentParser(description='ROCA TLS Fingerprinter')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--dump', dest='dump', default=False, action='store_const', const=True,
                            help='Dump all processed info')

        parser.add_argument('--flatten', dest='flatten', default=False, action='store_const', const=True,
                            help='Flatten the dump')

        parser.add_argument('--indent', dest='indent', default=False, action='store_const', const=True,
                            help='Indent the dump')

        parser.add_argument('--hosts', dest='hosts', default=False, action='store_const', const=True,
                            help='Arguments are host names not file names')

        parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='files to process')
        return parser

    def main(self):
        """
        Main entry point
        :return:
        """
        parser = self.init_parser()
        if len(sys.argv) < 2:
            parser.print_usage()
            sys.exit(0)

        self.args = parser.parse_args()
        self.roca.args.flatten = self.args.flatten
        self.roca.args.indent = self.args.indent

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)
            self.roca.args.debug = True

        self.work()


def main():
    app = RocaTLSFingerprinter()
    app.main()


if __name__ == "__main__":
    main()
