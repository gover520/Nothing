#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib
from urllib import request, parse
import json
import sys
import time
import signal
import subprocess


dnspod_username = '******@qq.com'
dnspod_password = '******'
dnspod_domains = [
	{
		'domain'		:	'outmai.cn',
		'sub_domain'	:	['pi','@', '*'],
		'inet_domain'	:	['inet']
	}
]
dnspod_daemon = 300


_dnspod_api = 'https://api.dnspod.com/'
_dnspod_myip = '127.0.0.1'
_dnspod_inetip = '127.0.0.1'
_dnspod_token = None


def api_call(api):
	if api == 'auth':
		return _dnspod_api + 'Auth'
	elif api == 'domain.info':
		return _dnspod_api + 'Domain.Info'
	elif api == 'records.list':
		return _dnspod_api + 'Record.List'
	elif api == 'records.modify':
		return _dnspod_api + 'Record.Modify'


def url_read(url, postdata = None, method = None):
	result = None

	if not postdata is None:
		postdata = urllib.parse.urlencode(postdata)

	try:
		req = urllib.request.Request(url)
		req.add_header('User-Agent', 'DNSPOD International DDNS/1.1.0 (jenson.shixf@gmail.com)')
		if not method is None:
			req.get_method = lambda: method
		urlItem = urllib.request.urlopen(req, data = postdata.encode('utf-8'), timeout = 10)
		result = urlItem.read()
		urlItem.close()
	except urllib.request.URLError as e:
		output_lasterror('URLError', e.reason)
	except urllib.request.HTTPError as e:
		output_lasterror('HTTPError', e.reason)
	except:
		output_lasterror('FetchError', 'HTTP data fetch error.')

	return result


def get_myip():
	#myip = url_read('http://shixf.com/api/getip')
	
	cmd = ''' curl ip.cip.cc '''
	myip = subprocess.getoutput(cmd)
	
	if not myip is None:
		global _dnspod_myip
		if myip != _dnspod_myip:
			_dnspod_myip = myip
			return _dnspod_myip
	return None

def get_inetip():
	cmd = ''' ifconfig -a '''
	result = subprocess.getoutput(cmd)

	inetip = result.split('inet ')[1]
	if not inetip is None:
		global _dnspod_inetip
		if inetip != _dnspod_inetip:
			_dnspod_inetip = inetip
			return _dnspod_inetip
	return None

def output_lasterror(error, message):
	print('{0} : {1}'.format(error, message))


def dnspod_login():
	postdata = {
		'login_email'		:		dnspod_username,
		'login_password'	:		dnspod_password,
		'format'			:		'json',
	}
	login_status = url_read(api_call('auth'), postdata)
	if not login_status is None:
		auth = json.loads(login_status)

		if '1' == auth['status']['code']:
			global _dnspod_token
			_dnspod_token = auth['user_token']
			return True
		else:
			output_lasterror('DnspodErrorCode: {0}'.format(auth['status']['code']), 
								auth['status']['message'])

	return False


def dnspod_domainid(domain):
	postdata = {
		'user_token'	:		_dnspod_token,
		'domain'		:		domain,
		'format'		:		'json',
	}
	domain_info = url_read(api_call('domain.info'), postdata)
	if not domain_info is None:
		info = json.loads(domain_info)

		if '1' == info['status']['code']:
			return int(info['domain']['id'])
		else:
			output_lasterror('DnspodErrorCode: {0}'.format(info['status']['code']), 
								info['status']['message'])
	return -1


def dnspod_records(domain_id):
	postdata = {
		'user_token'	:		_dnspod_token,
		'domain_id'		:		domain_id,
		'format'		:		'json',
	}
	records_status = url_read(api_call('records.list'), postdata)
	if not records_status is None:
		records = json.loads(records_status)

		if '1' == records['status']['code']:
			return records['records']
		else:
			output_lasterror('DnspodErrorCode: {0}'.format(records['status']['code']), 
								records['status']['message'])
	return None


def dnspod_record_modify(domain, domain_id, record, dnspod_ip):
	postdata = {
		'user_token'	:	_dnspod_token,
		'domain_id'		:	domain_id,
		'record_id'		:	record['id'],
		'sub_domain'	:	record['name'],
		'record_type'	:	record['type'],
		'record_line'	:	'default',
		'value'			:	dnspod_ip,
		'ttl'			:	record['ttl'],
		'format'		:	'json',
	}
	modify_status = url_read(api_call('records.modify'), postdata)
	if not modify_status is None:
		modify_result = json.loads(modify_status)

		if '1' == modify_result['status']['code']:
			output_lasterror('Success', 
				'{0}.{1} has changed IP to {2}, {3}'.format(record['name'], domain['domain'], 
					dnspod_ip, modify_result['status']['message']))
		else:
			output_lasterror('DnspodErrorCode: {0}'.format(modify_result['status']['code']), 
								modify_result['status']['message'])
		return True
	return False


def dnspod_checkrecords(domain, domain_id):
	records = dnspod_records(domain_id)
	if not records is None:
		for record in records:
			if record['name'] in domain['sub_domain']:
				if record['type'] == 'A' or record['type'] == 'AAAA':
					if record['value'] != _dnspod_myip:
						dnspod_record_modify(domain, domain_id, record, _dnspod_myip)
					else:
						output_lasterror('Success', 
							'{0}.{1} IP is not change.'.format(record['name'], domain['domain']))
			if record['name'] in domain['inet_domain']:
				if record['type'] == 'A' or record['type'] == 'AAAA':
					if record['value'] != _dnspod_inetip:
						dnspod_record_modify(domain, domain_id, record, _dnspod_inetip)
					else:
						output_lasterror('Success', 
							'{0}.{1} IP is not change.'.format(record['name'], domain['domain']))


def dnspod_ddns():
	if (get_myip() or get_inetip()) and dnspod_login():
		for domain in dnspod_domains:
			domain_id = dnspod_domainid(domain['domain'])
			if domain_id > 0:
				dnspod_checkrecords(domain, domain_id)


def _signal_handler(signal, frame):
	print('Exiting...')
	sys.exit(0)

if __name__ == '__main__':
	if len(sys.argv) >= 2 and sys.argv[1] == 'daemon':
		signal.signal(signal.SIGINT, _signal_handler)
		print('You may pressed Ctrl + C to exit.')
		while(True):
			dnspod_ddns()
			time.sleep(dnspod_daemon)
	else:
		dnspod_ddns()
