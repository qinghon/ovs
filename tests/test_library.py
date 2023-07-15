import unittest
import platform
from util import *


class Library(unittest.TestCase):
    def test_flow_extractor(self):
        stdout, stderr, code = run_binary_file('flowgen.py')
        self.assertEqual(code, 0)
        stdout, stderr, code = run_binary_file('ovstest', args=['test-flows', 'flows', 'pcap'])
        self.assertEqual(code, 0)
        self.assertIn("checked 247 packets, 0 errors", stdout)
        # self.assertEqual(True, False)  # add assertion here

    def test_tcpip_checksumming(self):
        stdout, stderr, code = run_binary_file('ovstest', args=['test-csum'])
        self.assertEqual(code, 0)
        self.assertIn("....#....#....####................................#................................#", stdout)

    def test_hash_function(self):
        stdout, stderr, code = run_binary_file('ovstest', args=['test-hash'])
        self.assertEqual(code, 0)

    def test_hash_map(self):
        stdout, stderr, code = run_binary_file('ovstest', args=['test-hmap'])
        self.assertEqual(code, 0)
        self.assertIn("............", stdout)

    def test_hash_index(self):
        stdout, stderr, code = run_binary_file('ovstest', args=['test-hindex'])
        self.assertEqual(code, 0)
        self.assertIn(".....................", stdout)

    def test_rcu_linked_lists(self):
        stdout, stderr, code = run_binary_file('ovstest', args=['test-rculist'])
        self.assertEqual(code, 0)
        self.assertIn(".....", stdout)

    def test_cuckoo_hash(self):
        """ cuckoo hash"""
        stdout, stderr, code = run_binary_file('ovstest', args=['test-cmap', 'check', '1'])
        self.assertEqual(code, 0)
        self.assertIn("...", stdout)

    def test_ccuckoo_hash(self):
        """ counting cuckoo hash"""
        stdout, stderr, code = run_binary_file('ovstest', args=['test-ccmap', 'check', '1'])
        self.assertEqual(code, 0)
        self.assertIn("...", stdout)

    def test_atomic_operations(self):
        """ atomic operations"""
        stdout, stderr, code = run_binary_file('ovstest', args=['test-atomic'])
        self.assertEqual(code, 0)

    def test_test_linked_lists(self):
        stdout, stderr, code = run_binary_file("ovstest", args=['test-list'])
        self.assertEqual(code, 0)
        self.assertIn("""....""", stdout)

    def test_packet_library(self):
        stdout, stderr, code = run_binary_file("ovstest", args=['test-packets'])
        self.assertEqual(code, 0)

    def test_sha1(self):
        """sha_1"""
        stdout, stderr, code = run_binary_file("ovstest", args=['test-sha1'])
        self.assertEqual(code, 0)
        self.assertIn("""....................""", stdout)

    def test_skiplist(self):
        """test_skiplist"""
        stdout, stderr, code = run_binary_file("ovstest", args=['test-skiplist'])
        self.assertEqual(code, 0)
        self.assertIn("""skiplist insert
skiplist delete
skiplist find
skiplist forward_to
skiplist random""", stdout)

    def test_type_properties(self):
        stdout, stderr, code = run_binary_file("test_props", args=None)
        self.assertEqual(code, 0)

    def test_strtok_r_bug_fix(self):
        stdout, stderr, code = run_binary_file("test_strtok_r", args=None)
        self.assertEqual(code, 0)
        self.assertIn("""NULL NULL""", stdout)

    def test_byte_order(self):
        """byte_order_conversion"""
        stdout, stderr, code = run_binary_file("ovstest", args=['test-byte-order'])
        self.assertEqual(code, 0)

    def test_random_number_generator(self):
        """byte_order_conversion"""
        stdout, stderr, code = run_binary_file("ovstest", args=['test-random'])
        self.assertEqual(code, 0)
        self.assertIn("""average=7fa2014f

bit      0     1
  0  4946  5054
  1  4939  5061
  2  4947  5053
  3  4935  5065
  4  5004  4996
  5  4998  5002
  6  5062  4938
  7  5009  4991
  8  5001  4999
  9  5022  4978
 10  5006  4994
 11  5039  4961
 12  4940  5060
 13  5048  4952
 14  4930  5070
 15  4973  5027
 16  4954  5046
 17  5043  4957
 18  5020  4980
 19  5104  4896
 20  5051  4949
 21  5003  4997
 22  5110  4890
 23  4950  5050
 24  5016  4984
 25  5019  4981
 26  4948  5052
 27  4995  5005
 28  4995  5005
 29  4969  5031
 30  5109  4891
 31  4984  5016
(expected values are 5000)

nibble   0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
     0 640 589 610 613 588 632 650 613 582 646 627 640 612 650 637 671
     1 626 642 663 620 630 609 617 602 615 638 614 644 641 597 598 644
     2 667 611 617 613 609 629 642 651 604 641 594 659 651 610 617 585
     3 621 662 594 605 618 644 616 613 613 616 611 608 614 660 653 652
     4 641 668 621 664 619 624 625 642 624 629 607 566 599 639 618 614
     5 666 629 620 621 581 615 598 620 630 651 671 622 628 603 657 588
     6 620 640 621 606 603 644 628 633 620 597 653 591 637 658 634 615
     7 636 645 679 593 598 609 612 612 623 626 638 669 603 629 606 622
(expected values are 625)""", stdout)

    def test_util_case(self):
        cases = ['ctz', 'clz', 'round_up_pow2', 'round_down_pow2', 'count_1bits',
                 'log_2_floor', 'bitwise_copy', 'bitwise_zero', 'bitwise_one',
                 'bitwise_is_all_zeros', 'bitwise_rscan', 'ovs_scan']
        for case_name in cases:
            with self.subTest(case_name=case_name):
                stdout, stderr, code = run_binary_file("ovstest", args=['test-util', case_name])
                self.assertEqual(code, 0)

    def test_unix_socket_short_pathname__c(self):
        """unix socket, short pathname - C"""
        stdout, stderr, code = run_binary_file("ovstest", args=['test-unix-socket', 'x'])
        self.assertEqual(code, 0)

    @unittest.skipIf(platform.system() == 'Windows', "Skipping on Windows")
    def test_unix_socket_long_pathname_c(self):
        """ Unix sockets with long names are problematic because the name has to
            go in a fixed-length field in struct sockaddr_un.  Generally the limit
            is about 100 bytes.  On Linux, we work around this by indirecting through
            a directory fd using /proc/self/fd/<dirfd>.  We do not have a workaround
            for other platforms, so we skip the test there.
        :return:
        """
        longname = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012"
        try:
            os.makedirs(longname, exist_ok=True)
        except BaseException:
            self.skipTest("system doesn't support such long names ")
            return
        stdout, stderr, code = run_binary_file("ovstest",
                                               args=['test-unix-socket', '../' + longname + '/socket', 'socket'],
                                               cwd=os.path.abspath(longname))
        os.rmdir(longname)
        self.assertEqual(code, 0)

    def test_python_unixsocket(self):
        """unix_socket_short_pathname__python3"""
        stdout, stderr, code = run_python_file(os.path.join(os.getenv("SRC_DIR"), "test-unix-socket.py"), args=['x'])
        self.assertEqual(code, 0)


    @unittest.skipIf(platform.system() == 'Windows', "Skipping on Windows")
    def test_unix_socket_long_pathname_python(self):
        """ Unix sockets with long names are problematic because the name has to
            go in a fixed-length field in struct sockaddr_un.  Generally the limit
            is about 100 bytes.  On Linux, we work around this by indirecting through
            a directory fd using /proc/self/fd/<dirfd>.  We do not have a workaround
            for other platforms, so we skip the test there.
        :return:
        """
        longname = "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012"
        try:
            os.makedirs(longname, exist_ok=True)
        except BaseException:
            self.skipTest("system doesn't support such long names ")
            return
        stdout, stderr, code = run_python_file(os.path.join(os.getenv("SRC_DIR"),"test-unix-socket.py"),
                                               args=['../' + longname + '/socket', 'socket'],
                                               cwd=os.path.abspath(longname))
        os.rmdir(longname)
        self.assertEqual(code, 0)

    def test_assert(self):

        if platform.system() == 'Windows':
            exit_code = 9
        else:
            # SIGABRT + 128
            exit_code = 134

        stdout, assertstderr, code = run_binary_file("ovstest", args=["test-util", "-voff",
                                                                      "-vfile:info", '-vPATTERN:file:%c|%p|%m',
                                                                      "--log-file=test-util.log", "assert"])

        self.assertEqual(code, exit_code)
        # print("stdout:", stdout, "stderr:", assertstderr)
        logstr = ""
        with open("test-util.log") as f:
            logstr = f.read()
        os.remove("test-util.log")
        self.assertIn("vlog|INFO|opened log file", logstr)
        self.assertRegex(logstr, "util|EMER|[.*?]: assertion false failed in test_assert()")


    def test_sat_math_sat_math(self):
        """saturating arithmetic"""
        stdout, stderr, code = run_binary_file("ovstest", args=['test-util', 'sat_math'])
        self.assertEqual(code, 0)

    def test_snprintf(self):
        stdout, stderr, code = run_binary_file("ovstest", args=['test-util', 'snprintf'])
        self.assertEqual(code, 0)

    def test_bitmap_functions(self):
        stdout, stderr, code = run_binary_file("ovstest", args=['test-bitmap', 'check'])
        self.assertEqual(code, 0)
        self.assertIn("""..""", stdout)

    def test_use_of_public_headers(self):
        stdout, stderr, code = run_binary_file("test-lib", args=None)
        self.assertEqual(code, 0)

    def test_ofpbuf_module(self):
        stdout, stderr, code = run_binary_file("ovstest", args=['test-ofpbuf'])
        self.assertEqual(code, 0)

    def test_barrier(self):
        """barrier_module"""
        stdout, stderr, code = run_binary_file("ovstest", args=['test-barrier'])
        self.assertEqual(code, 0)

    def test_rcu(self):
        stdout, stderr, code = run_binary_file("ovstest", args=['test-rcu'])
        self.assertEqual(code, 0)

    def test_stopwatch_module(self):
        stdout, stderr, code = run_binary_file("ovstest", args=['test-stopwatch'])
        self.assertEqual(code, 0)
        self.assertIn("""......""", stdout)

    @unittest.skipIf(platform.system() in ['Windows'] or "bsd" in sys.platform, "not on win or bsd")
    def test_netlink_policy(self):
        stdout, stderr, code = run_binary_file("ovstest", args=['test-netlink-policy', 'll_addr'])
        self.assertEqual(code, 0)

    def test_mpsc_queue_module(self):
        stdout, stderr, code = run_binary_file("ovstest", args=['test-mpsc-queue', 'check'])
        self.assertEqual(code, 0)
        self.assertIn("""....""", stdout)

    def test_id_fpool_module(self):
        stdout, stderr, code = run_binary_file("ovstest", args=['test-id-fpool', 'check'])
        self.assertEqual(code, 0)

    def test_uuidset_module(self):
        stdout, stderr, code = run_binary_file("ovstest", args=['test-uuidset'])
        self.assertEqual(code, 0)


if __name__ == '__main__':
    unittest.main()
