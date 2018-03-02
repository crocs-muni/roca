import sys

from setuptools import setup
from setuptools import find_packages

version = '1.2.12'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    'cryptography>=1.2.3',
    'setuptools>=1.0',
    'six',
    'future',
    'coloredlogs',
    'pgpdump',
    'python-dateutil',
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

apk_jks_extras = [
    'apk_parse_ph4>=0.1.7',
    'pyjks',
]

try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
    long_description = long_description.replace("\r", '')

except(IOError, ImportError):
    import io
    with io.open('README.md', encoding="utf-8") as f:
        long_description = f.read()

setup(
    name='roca-detect',
    version=version,
    description='ROCA key detector / fingerprinter tool',
    long_description=long_description,
    url='https://github.com/crocs-muni/roca',
    author='Dusan Klinec',
    author_email='dusan.klinec@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    python_requires='>=2.7.10,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*',
    install_requires=install_requires,
    extras_require={
        'dev': dev_extras,
        'docs': docs_extras,
        'apk-jks': apk_jks_extras,
    },

    entry_points={
        'console_scripts': [
            'roca-detect = roca.detect:main',
            'roca-detect-tls = roca.detect_tls:main',
        ],
    }
)
