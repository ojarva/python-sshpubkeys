""" Creates tests from lists of both valid and invalid keys.

New test is generated for each key so that running unittests gives out meaningful errors.

"""

import unittest
from sshpubkeys import *
from .valid_keys import keys as list_of_valid_keys
from .valid_keys_rfc4716 import keys as list_of_valid_keys_rfc4716
from .invalid_keys import keys as list_of_invalid_keys


class TestKeys(unittest.TestCase):
    def check_key(self, pubkey, bits, fingerprint_md5, fingerprint_sha256):
        """ Checks valid key """
        ssh = SSHKey(pubkey)
        self.assertEqual(ssh.bits, bits)
        self.assertEqual(ssh.hash_md5(), fingerprint_md5)
        if fingerprint_sha256 is not None:
            self.assertEqual(ssh.hash_sha256(), fingerprint_sha256)

    def check_fail(self, pubkey, expected_error):
        """ Checks that key check raises specified exception """
        # Don't use with statement here - it does not work with Python 2.6 unittest module
        self.assertRaises(expected_error, SSHKey, pubkey)


def loop_valid(keyset, prefix):
    """ Loop over list of valid keys and dynamically create tests """
    for i, items in enumerate(keyset):
        def ch(pubkey, bits, fingerprint_md5, fingerprint_sha256):
            return lambda self: self.check_key(pubkey, bits, fingerprint_md5, fingerprint_sha256)
        prefix_tmp = "%s_%s" % (prefix, i)
        prefix_tmp = items.pop()
        pubkey, bits, fingerprint_md5, fingerprint_sha256 = items
        setattr(TestKeys, "test_%s" % prefix_tmp, ch(pubkey, bits, fingerprint_md5, fingerprint_sha256))


def loop_invalid(keyset, prefix):
    """ Loop over list of invalid keys and dynamically create tests """
    for i, items in enumerate(keyset):
        def ch(pubkey, expected_error):
            return lambda self: self.check_fail(pubkey, expected_error)
        prefix_tmp = "%s_%s" % (prefix, i)
        if len(items) == 3:  # If there is an extra item, use that as test name.
            prefix_tmp = items.pop()
        pubkey, expected_error = items
        setattr(TestKeys, "test_%s" % prefix_tmp, ch(pubkey, expected_error))

loop_valid(list_of_valid_keys, "valid_key")
loop_valid(list_of_valid_keys_rfc4716, "valid_key_rfc4716")
loop_invalid(list_of_invalid_keys, "invalid_key")

if __name__ == '__main__':
    unittest.main()
