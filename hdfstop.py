#!/usr/bin/env python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

#------------------------- Documentation Start --------------------------------#
DOCUMENTATION = '''
---
version: "1.0.0"

program: hdfstop

short_description: HDFSTOP NameNode Audit Log Challenge

description:
  - Program to output the grouped results of a NameNode audit log file
  	based on one or more fields, in descending order of the count

options:
    ugi:
    	description: user id

	cmd:
		description: operation requested by the client

	src:
		description: file or directory in HDFS

	ip:
		description: IP address of client node

	ldate:
		description: date

	tmstamp:
		description: time stamp

	allowed:
		description: operation was allowed or denied

requirements: [OS: OL/RHEL/CentOS 6/7 with Python]

author: Vineela Reddy N
'''

EXAMPLES = '''
./hdfstop -audit_log <path_to_file> -group_by ugi,cmd -limit 15

hbase getfileinfo 20747
hbase delete 20627
jane contentSummary 20555
jane delete 20539
hbase create 20272
hbase contentSummary 19457
...

./hdfstop --audit_log /tmp/hdfs-audit.log --group_by ugi,src --limit 10

./hdfstop --audit_log /tmp/hdfs-audit.log --group_by ugi,cmd,src --limit 10

./hdfstop --audit_log /tmp/hdfs-audit.log --group_by cmd,src --limit 10

'''
# Check Python version
import sys

if sys.version_info < (2, 6):
    raise UnsupportedPythonVersionError(sys.version)

#import directives
import argparse
import logging
from logging import config
import os

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(module)s.%(funcName)s: %(message)s'
        },
    },
    'handlers': {
        'stdout': {
            'class': 'logging.StreamHandler',
            'stream': sys.stdout,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'hdfstop-logger': {
            'handlers': ['stdout'],
            'level': logging.INFO,
            'propagate': True,
        },
    }
}

config.dictConfig(LOGGING)
log = logging.getLogger("hdfstop-logger")

def read_file(infile=None):
	"""
	function to read file into memory, for better performance.
	can also read from the file directly, line by line for better memory usage
	"""

	file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), infile)
	file_data = list()

	if os.path.exists(file_path):
		try:
			with open(file_path) as fread:
				file_data = fread.readlines()
		except IOError as ie:
			sys.exit("Could not read file : %s" % str(fe))
		else:
			fread.close()
			return file_data
	else:
		sys.exit("File not found error")

def parse_input_args():
	"""
	function to handle the input arguments to filter and group the results
	from the audit log file using argparse module
	"""

	parser = argparse.ArgumentParser()
	parser.add_argument(
						"-a",
						"--audit_log",
						type=str,
						help='path to the audit log file',
						required = True)
	parser.add_argument(
						"-g",
						"--group_by",
						type=str,
						help='one or more comma separated fields to group the results',
						required = True)
	parser.add_argument(
						"-l",
						"--limit",
						type=int,
						help='count to limit the number of records',
						required = True)

	args = parser.parse_args()
	audit_log, groupby_list, limit = args.audit_log, args.group_by, args.limit
	return (audit_log, groupby_list, limit)

def get_record_string(inline, groupby_list):
	"""
	function to extract the row matching the group of input fields
	"""

	(ldate,
	tmstamp,
	level,
	audit,
	allowed,
	ugi,
	auth,
	ip,
	cmd,
	src,
	dst,
	perm,
	proto) = inline.split()

	record_string = str()

	if 'ldate' in groupby_list:
		record_string += ldate

	if 'tmstamp' in groupby_list:
		tm_value = tmstamp.split(',')[0]
		record_string = record_string + ' ' + tm_value

	if 'level' in groupby_list:
		record_string = record_string + ' ' + level

	if 'audit' in groupby_list:
		record_string = record_string + ' ' + audit

	if 'allowed' in groupby_list:
		is_allowed = allowed.split('=')[1]
		record_string = record_string + ' ' + is_allowed

	if 'ugi' in groupby_list:
		ugi_value = ugi.split('=')[1]
		record_string = record_string + ' ' + ugi_value

	if 'auth' in groupby_list:
		auth_value = auth.split(':')[1]
		record_string = record_string + ' ' + auth_value

	if 'ip' in groupby_list:
		ip_value = ip.split('=/')[1]
		record_string = record_string + ' ' + ip_value

	if 'cmd' in groupby_list:
		cmd_value = cmd.split('=')[1]
		record_string = record_string + ' ' + cmd_value

	if 'src' in groupby_list:
		src_value = src.split('=')[1]
		record_string = record_string + ' ' + src_value

	if 'dst' in groupby_list:
		dst_value = dst.split('=')[1]
		record_string = record_string + ' ' + dst_value

	if 'perm' in groupby_list:
		perm_value = perm.split('=')[1]
		record_string = record_string + ' ' + perm_value

	if 'proto' in groupby_list:
		proto_value = proto.split('=')[1]
		record_string = record_string + ' ' + proto_value

	return record_string.strip()

def print_results_format(output_list, limit, count_index):
	"""
	function to output the results in descending order
	limited to a given count
	"""

	output_list.sort(key = lambda x: int(x[count_index]), reverse=True)
	for each_elem in output_list[0:limit]:
		print(' '.join(map(str, each_elem)))

def add_record(record_string, output_list):
	"""
	function to add first occurrence of a record to the output list
	"""

	record_string = record_string + ' ' + str(1)
	record_list = record_string.split()
	output_list.append(record_list)

def check_increment_record(isFound, record_string, output_list, count_index):
	"""
	function to check for a given record,
	if a matching record is found in the output_list,
	increment the count, break the iteration and return isFound True
	"""

	for each_record in output_list:
		if set(record_string.split()) <= set(each_record):
			try:
				each_record[count_index] = str(int(each_record[count_index]) + 1)
			except IndexError as ierror:
				raise Exception("Index error : %s" % str(ierror))

			isFound = True
			break

	return isFound

def process_results(record_string, output_list, count_index):
	"""
	function to add the record string if not present in the output list
	increment the count for the record string if a match in the output list
	"""

	isFound = False

	if len(output_list) > 0:
		isFound = check_increment_record(isFound,
										record_string,
										output_list,
										count_index)
		if isFound is not True:
			add_record(record_string, output_list)
	else:
		add_record(record_string, output_list)

def main():
	""" main function to be executed """

	# get the input arguments
	(audit_log, group_by, limit) = parse_input_args()

	# split and store the fields into a list
	groupby_list = group_by.split(',')

	# get the index of the count element
	count_index = len(groupby_list)

	# initialize the output results list
	output_list = list()

	# read audit log file into memory
	file_data = read_file(audit_log)

	# read through each line of file from memory
	for each_line in file_data:
		# extract the record string from the line matching the group of fields
		record_string = get_record_string(each_line,
										  groupby_list)
		# add or increment the record to the output list
		process_results(record_string,
						output_list,
						count_index)

	# print the complete results limit to a number in descending order
	print_results_format(output_list,
				  limit,
				  count_index)

if __name__ == '__main__':
	main()
