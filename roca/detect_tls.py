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
from detect import RocaFingerprinter, logger, LOG_FORMAT
from ssl import get_server_certificate


#
# Main class
#
class RocaTLSFingerprinter(object):
    """
    TLS fingerprinter
    """

    def __init__(self):
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
                host,port = line.split(':')
                pem_cert = self.get_server_certificate(host, port)
                if pem_cert:
                    sub = self.roca.process_pem_cert(pem_cert, name, idx)
                    ret.append(sub)

        except Exception as e:
            logger.error('Error in file processing %s : %s' % (name, e))
            self.trace_logger.log(e)
        return ret

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
            fh = open(fname, 'rb')
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

        self.work()


def main():
    app = RocaTLSFingerprinter()
    app.main()


if __name__ == "__main__":
    main()
