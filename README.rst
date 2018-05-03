OpenSSH Public Key Parser for Python
====================================

.. image:: https://travis-ci.org/ojarva/python-sshpubkeys.svg?branch=master
    :target: https://travis-ci.org/ojarva/python-sshpubkeys

Major changes between versions 2 and 3
--------------------------------------

- Dropped support for Python 2.6 and 3.3
- Even in loose mode, DSA keys must be 1024, 2048, or 3072 bits (earlier this was looser)
- The interface (API) is exactly the same


Usage
-----

Native implementation for validating OpenSSH public keys.

Currently ssh-rsa, ssh-dss (DSA), ssh-ed25519 and ecdsa keys with NIST curves are supported.

Installation:

::

  pip install sshpubkeys

or clone the `repository <https://github.com/ojarva/sshpubkeys>`_ and use

::

  python setup.py install

Usage:

::

  import sys
  from sshpubkeys import SSHKey

  ssh = SSHKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAYQCxO38tKAJXIs9ivPxt7AY"
        "dfybgtAR1ow3Qkb9GPQ6wkFHQqcFDe6faKCxH6iDRteo4D8L8B"
        "xwzN42uZSB0nfmjkIxFTcEU3mFSXEbWByg78aoddMrAAjatyrh"
        "H1pON6P0= ojarva@ojar-laptop", strict=True)
  try:
      ssh.parse()
  except InvalidKeyError as err:
      print("Invalid key:", err)
      sys.exit(1)
  except NotImplementedError as err:
      print("Invalid key type:", err)
      sys.exit(1)

  print(ssh.bits)  # 768
  print(ssh.hash_md5())  # 56:84:1e:90:08:3b:60:c7:29:70:5f:5e:25:a6:3b:86
  print(ssh.hash_sha256())  # SHA256:xk3IEJIdIoR9MmSRXTP98rjDdZocmXJje/28ohMQEwM
  print(ssh.hash_sha512())  # SHA512:1C3lNBhjpDVQe39hnyy+xvlZYU3IPwzqK1rVneGavy6O3/ebjEQSFvmeWoyMTplIanmUK1hmr9nA8Skmj516HA
  print(ssh.comment)  # ojar@ojar-laptop
  print(ssh.options_raw)  # None (string of optional options at the beginning of public key)
  print(ssh.options)  # None (options as a dictionary, parsed and validated)


Parsing of `authorized_keys` files:

::

  from sshpubkeys import AuthorizedKeysFile
  f = open("/home/username/.ssh/authorized_keys", "r")
  key_file = AuthorizedKeysFile(f, strict=False)

  for key in key_file.keys:
      print(key.key_type, key.bits, key.comment)


Options
-------

Set options in constructor as a keywords (i.e., `SSHKey(None, strict=False)`)

- strict: defaults to True. Disallows keys OpenSSH's ssh-keygen refuses to create. For instance, this includes DSA keys where length != 1024 bits and RSA keys shorter than 1024-bit. If set to False, tries to allow all keys OpenSSH accepts, including highly insecure 1-bit DSA keys.
- skip_option_parsing: if set to True, options string is not parsed (ssh.options_raw is populated, but ssh.options is not).
- disallow_options: if set to True, options are not allowed and it will raise an
  InvalidOptionsError.

Exceptions
----------

- NotImplementedError if invalid ecdsa curve or unknown key type is encountered.
- InvalidKeyError if any other error is encountered:
    - TooShortKeyError if key is too short (<768 bits for RSA, <1024 for DSA, <256 for ED25519)
    - TooLongKeyError if key is too long (>16384 for RSA, >1024 for DSA, >256 for ED25519)
    - InvalidTypeError if key type ("ssh-rsa" in above example) does not match to what is included in base64 encoded data.
    - MalformedDataError if decoding and extracting the data fails.
    - InvalidOptionsError if options string is invalid.
        - InvalidOptionNameError if option name contains invalid characters.
            - UnknownOptionNameError if option name is not recognized.
        - MissingMandatoryOptionValueError if option needs to have parameter, but it is absent.

Tests
-----

See "`tests/ <https://github.com/ojarva/sshpubkeys/tree/master/tests>`_" folder for unit tests. Use

::

  python setup.py test

or

::

  python3 setup.py test

to run test suite. If you have keys that are not parsed properly, or malformed keys that raise incorrect exception, please send your *public key* to olli@jarva.fi, and I'll include it. Alternatively, `create a new issue <https://github.com/ojarva/sshpubkeys/issues/new>`_ or make `a pull request <https://github.com/ojarva/sshpubkeys/compare>`_ in github.
