from setuptools import setup
from codecs import open as codecs_open
from os import path

here = path.abspath(path.dirname(__file__))

with codecs_open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='sshpubkeys',
    version='2.3.0',
    description='SSH public key parser',
    long_description=long_description,
    url='https://github.com/ojarva/python-sshpubkeys',
    author='Olli Jarva',
    author_email='olli@jarva.fi',
    license='BSD',

    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'License :: OSI Approved :: BSD License',

        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: Implementation :: PyPy',
    ],
    keywords='ssh pubkey public key openssh ssh-rsa ssh-dss ssh-ed25519',
    packages=["sshpubkeys"],
    test_suite="tests",
    install_requires=['pycrypto>=2.6', 'ecdsa>=0.13'],

    extras_require={
        'dev': ['twine', 'wheel'],
    },
)
