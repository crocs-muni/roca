import sys

from setuptools import setup
from setuptools import find_packages

version = '0.0.0'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    'pycrypto>=2.6',
    'cryptography',
    'setuptools>=1.0',
    'six',
    'future',
    'coloredlogs',
    'pgpdump',
    'apk_parse_ph4>=0.1.7',
    'pyx509_ph4',
    'python-dateutil'
]

dev_extras = [
    'nose',
    'pep8',
    'tox',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
    'sphinxcontrib-programoutput',
]

setup(
    name='fingerprinter',
    version=version,
    description='Key fingerprinting tools',
    url='https://github.com/ph4r05/',
    author='Dusan Klinec',
    author_email='dusan.klinec@gmail.com',
    license='GPL',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'dev': dev_extras,
        'docs': docs_extras,
    }
)
