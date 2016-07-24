""" Creates tests from lists of both valid and invalid keys.

New test is generated for each key so that running unittests gives out meaningful errors.

"""

import unittest
from sshpubkeys import *
from .valid_keys import keys as list_of_valid_keys
from .valid_keys_rfc4716 import keys as list_of_valid_keys_rfc4716
from .invalid_keys import keys as list_of_invalid_keys


class TestKeys(unittest.TestCase):
    def check_key(self, pubkey, bits, fingerprint_md5, fingerprint_sha256, **kwargs):
        """ Checks valid key """
        ssh = SSHKey(pubkey, **kwargs)
        ssh.parse()
        self.assertEqual(ssh.bits, bits)
        self.assertEqual(ssh.hash_md5(), fingerprint_md5)
        if fingerprint_sha256 is not None:
            self.assertEqual(ssh.hash_sha256(), fingerprint_sha256)

    def check_fail(self, pubkey, expected_error, **kwargs):
        """ Checks that key check raises specified exception """
        # Don't use with statement here - it does not work with Python 2.6 unittest module
        ssh_key = SSHKey(pubkey, **kwargs)
        self.assertRaises(expected_error, ssh_key.parse)


def loop_valid(keyset, prefix):
    """ Loop over list of valid keys and dynamically create tests """
    def ch(pubkey, bits, fingerprint_md5, fingerprint_sha256, **kwargs):
        return lambda self: self.check_key(pubkey, bits, fingerprint_md5, fingerprint_sha256, **kwargs)
    for i, items in enumerate(keyset):
        modes = items.pop()
        prefix_tmp = "%s_%s" % (prefix, items.pop())
        for mode in modes:
            if mode == "strict":
                kwargs = {"strict": True}
            else:
                kwargs = {"strict": False}
            pubkey, bits, fingerprint_md5, fingerprint_sha256 = items
            setattr(TestKeys, "test_%s_mode_%s" % (prefix_tmp, mode), ch(pubkey, bits, fingerprint_md5, fingerprint_sha256, **kwargs))


def loop_invalid(keyset, prefix):
    """ Loop over list of invalid keys and dynamically create tests """
    def ch(pubkey, expected_error, **kwargs):
        return lambda self: self.check_fail(pubkey, expected_error, **kwargs)
    for i, items in enumerate(keyset):
        modes = items.pop()
        prefix_tmp = "%s_%s" % (prefix, items.pop())
        for mode in modes:
            if mode == "strict":
                kwargs = {"strict": True}
            else:
                kwargs = {"strict": False}
            pubkey, expected_error = items
            setattr(TestKeys, "test_%s_mode_%s" % (prefix_tmp, mode), ch(pubkey, expected_error, **kwargs))

loop_valid(list_of_valid_keys, "valid_key")
loop_valid(list_of_valid_keys_rfc4716, "valid_key_rfc4716")
loop_invalid(list_of_invalid_keys, "invalid_key")

if __name__ == '__main__':
    unittest.main()
