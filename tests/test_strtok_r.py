import unittest

from util import *


class Strtok_r(unittest.TestCase):
    def test_strtok_r(self):
        stdout, stderr, code = run_binary_file('test_strtok_r')
        self.assertEqual(code, 0)
        self.assertEqual(stdout.strip(), "NULL NULL")
        # self.assertEqual(True, False)  # add assertion here


if __name__ == '__main__':
    unittest.main()
