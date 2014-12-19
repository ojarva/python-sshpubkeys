""" Creates tests from lists of both valid and invalid keys.

New test is generated for each key so that running unittests gives out meaningful errors.

"""

import unittest
from sshpubkeys import *
from .test_rsa_keys_lengths import keys as rsa_keys_l
from .test_rsa_keys_failing import keys as rsa_keys_f
from .test_dsa_keys import keys as dsa_keys
from .test_dsa_keys_failing import keys as dsa_keys_f
from .test_ecdsa_keys import keys as ecdsa_keys

class TestKeys(unittest.TestCase):
    def check_key(self, pubkey, bits, fingerprint):
        """ Checks valid key """
        ssh = SSHKey(pubkey)
        self.assertEqual(ssh.bits, bits)
        self.assertEqual(ssh.hash(), fingerprint)

    def check_fail(self, pubkey, expected_error):
        """ Checks that key check raises specified exception """
        # Don't use with statement here - it does not work with Python 2.6 unittest module
        self.assertRaises(expected_error, SSHKey, pubkey)
 
def loop_ok(keyset, prefix):
    """ Loop over list of valid keys and dynamically create tests """
    for i, items in enumerate(keyset):
        def ch(pubkey, bits, fingerprint):
            return lambda self: self.check_key(pubkey, bits, fingerprint)
        prefix_tmp = "%s_%s" % (prefix, i)
        if len(items) == 4: # If there is an extra item, use that as test name.
            prefix_tmp = items.pop()
        pubkey, bits, fingerprint = items
        setattr(TestKeys, "test_%s" % prefix_tmp, ch(pubkey, bits, fingerprint))

def loop_failing(keyset, prefix):
    """ Loop over list of invalid keys and dynamically create tests """
    for i, items in enumerate(keyset):
        def ch(pubkey, expected_error):
            return lambda self: self.check_fail(pubkey, expected_error)
        prefix_tmp = "%s_%s" % (prefix, i)
        if len(items) == 3: # If there is an extra item, use that as test name.
            prefix_tmp = items.pop()
        pubkey, expected_error = items
        setattr(TestKeys, "test_%s" % prefix_tmp, ch(pubkey, expected_error))

loop_ok(ecdsa_keys, "ecdsa_ok")
loop_ok(rsa_keys_l, "rsa_ok")
loop_ok(dsa_keys, "dsa_ok")
loop_failing(rsa_keys_f, "rsa_failing")
loop_failing(dsa_keys_f, "dsa_failing")

if __name__ == '__main__':
    unittest.main()
