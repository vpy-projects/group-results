#!/usr/bin/env python

import unittest
from hdfstop import get_record_string, check_increment_record

class TestStringMethods(unittest.TestCase):

    def test_record_string(self):
        line = "2016-05-06 18:01:45,603 INFO FSNamesystem.audit: allowed=true	ugi=root (auth:SIMPLE)	ip=/10.211.55.101	cmd=getfileinfo	src=/	dst=null	perm=null	proto=rpc"
        groupby_list = ['ugi', 'cmd']
        record_string = get_record_string(line, groupby_list)
        self.assertEqual('root getfileinfo', record_string)
        
    def test_is_record_present(self):
        output_list = [['root', 'getfileinfo', '2'], ['bar', 'create', '3'], ['jane', 'executescript', '4']]
        record_string = 'root getfileinfo'
        self.assertTrue(check_increment_record(False, record_string, output_list, 2))

if __name__ == '__main__':
    unittest.main()
