import json
import asyncio
import dns.resolver
import os
import socket
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import re
import IPy
from multiprocessing.pool import ThreadPool
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

loop = asyncio.get_event_loop()


class get_cdn(object):
	def __init__(self, target):
		self.target = target
		self.records = []
		self.ip_result = []
		self.cname_result = []

	async def query(self, dnsserver):
		try:
			Resolver = dns.resolver.Resolver()
			Resolver.lifetime = Resolver.timeout = 2.0
			Resolver.nameservers = dnsserver
			record = Resolver.resolve(self.target, "A")
			self.records.append(record)
		except Exception as e:
			# print(e)
			pass

	def check_cdn(self):
		dnsserver = [['114.114.114.114'], ['8.8.8.8'], ['223.6.6.6'], ['1.2.4.8'], ['208.67.222.222']]
		try:
			for i in dnsserver:
				loop.run_until_complete(self.query(i))
			for record in self.records:
				for m in record.response.answer:
					for j in m.items:
						if isinstance(j, dns.rdtypes.IN.A.A):
							self.ip_result.append(j.address)
						elif isinstance(j, dns.rdtypes.ANY.CNAME.CNAME):
							self.cname_result.append(j.to_text())
		except Exception as e:
			print(e)

	def getrules(self):
		with open('cname', encoding='utf-8') as f:
			cname_rules = json.load(f)
			f.close()
		return cname_rules

	def run(self):
		cdn_flag = 0
		self.check_cdn()
		if len(list(set(self.ip_result))) > 1:
			cdn_flag = 1

		if cdn_flag == 1:
			cdn_name = 'Unknow'
			cname_rules = self.getrules()
			for i in self.cname_result:
				domain_spilt = i.split('.')
				cdn_domain = '.'.join(domain_spilt[-3:])[:-1]
				if cdn_domain in cname_rules.keys():
					cdn_name = cname_rules[cdn_domain]['name']
					break
		else:
			cdn_name = 'no cdn'
		return cdn_name


class bypass_cdn(object):
	def __init__(self, target):
		self.headers = {
			'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36',
		}
		self.target = target.rstrip('/')
		self.ips = set()
		self.cidr_set = set()
		self.Root_Path = os.path.dirname(os.path.abspath(__file__))
		parse = urlparse(target)
		self.scheme = str(parse.scheme)
		self.netloc = str(parse.netloc)
		if self.scheme == "https":
			self.port = "443"
		else:
			self.port = "80"
		# 结果队列
		self.result = set()
		self.length = self.get_length(self.target)

	def get_length(self, target):
		times = 0
		while True:
			r = requests.get(target, headers=self.headers, timeout=5, verify=False)
			times = times + 1
			if len(r.content) != 0:
				return len(r.content)
			if times > 5:
				print("未能成功请求:" + target_url)
				return False

	# print(self.target)
	def get_ip(self):
		myaddr = socket.getaddrinfo(self.netloc, 'http')
		# print(myaddr[0][4][0])
		return str(myaddr[0][4][0])

	# self.result.append(str(myaddr[0][4][0]))
	def check_phpinfo(self):
		payloads = [
			"phpinfo.php",
			"pi.php",
			"php.php",
			"i.php",
			"test.php",
			"temp.php",
			"info.php",
		]
		headers = {
			'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36',
		}
		flag = "<title>phpinfo()</title>"
		patten = "[0-9]{1,}.[0-9]{1,}.[0-9]{1,}.[0-9]{1,}"
		for phpinfo in payloads:
			# test_url = self.scheme + "://" + self.target.rstrip('/') + "/" + phpinfo
			test_url = self.target.rstrip('/') + "/" + phpinfo
			try:
				r = requests.get(test_url, headers=headers, timeout=5, verify=False)
				if flag in r.text:
					soup = BeautifulSoup(r.text, 'html.parser')
					org_links = soup.find_all(name='tr')
					for i in org_links:
						if "SERVER_ADDR" in str(i):
							ret = str(re.compile(patten).findall(str(i)))
							ret = ret[2:-2]
							if not ret.startswith('192.168') and not ret.startswith('10.'):
								self.result.add(ret)
			except Exception as e:
				# print(e)
				pass

	def special_ping(self):
		if self.netloc.startswith('www.'):
			target_url = self.netloc[4:]
			name = get_cdn(target_url).run()
			if name == "no cdn":
				self.result.add(self.get_ip())

	# return get_ip(target_url)

	# return False

	def domain_history(self):
		target_url = "https://site.ip138.com/" + str(self.netloc) + "/"
		re_pattern_domain = re.compile(r'<p>.<span class="date">.*</span>.<a href=.* target="_blank">(.*)</a>.</p>',
									   re.DOTALL)
		headers = {
			'Accept': '*/*',
			'Accept-Language': 'en-US,en;q=0.8',
			'Cache-Control': 'max-age=0',
			'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36',
			'Connection': 'keep-alive',
			'Referer': 'http://www.baidu.com/'
		}
		# print(r.text)
		times = 0
		while True:
			r = requests.get(target_url, headers=headers, timeout=5)
			times = times + 1
			if r.status_code == 200:
				break
			if times > 5:
				print("[-] 未能成功请求DNS查询:" + target_url)
				return False
		soup = BeautifulSoup(r.text, 'html.parser')
		org_links = soup.find_all('p')
		for org_link in org_links:
			org_link = str(org_link)
			if (len(re_pattern_domain.findall(org_link))):
				self.ips.add(re_pattern_domain.findall(org_link)[0])

	def subscan(self):
		target = self.netloc
		if target.startswith('www.'):
			target = target[4:]
		os.chdir("subDomainsBrute")
		cmdline = "python3 subDomainsBrute.py {}".format(target)
		os.system(cmdline)
		# print(cmdline)
		os.chdir(self.Root_Path)
		sub_filename = "./subDomainsBrute/{}.txt".format(target)

		with open(sub_filename, "r") as f:
			content = f.read()
			for x in content.strip().split('\n'):
				try:
					domain, ips = x.split('\t')
					for _i in ips.split(','):
						# result.append(_i.strip())
						self.ips.add(_i.strip())
				except:
					pass

	def Cscan(self, target):
		patten = "[0-9]{1,}.[0-9]{1,}.[0-9]{1,}.[0-9]{1,}"
		ipadress = str(re.compile(patten).findall(target))[2:-2]
		# print("target:" + target)
		headers_1 = {
			'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36',
		}
		headers_2 = {
			'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36',
			'Host': ''.format(self.netloc),
		}
		host_len = 0
		no_host_len = 0
		try:
			r = requests.get(target, headers=headers_1, timeout=5, verify=False)
			if r.status_code == 200:
				no_host_len = len(r.content)
		except Exception as e:
			no_host_len = 0
			pass
		try:
			r = requests.get(target, headers=headers_2, timeout=5, verify=False)
			if r.status_code == 200:
				host_len = len(r.content)
		except Exception as e:
			host_len = 0
			pass
		if host_len != 0 or no_host_len != 0:
			print("[*] %-15s\t%-6s\t%-6s" % (ipadress, no_host_len, host_len))
		if host_len == self.length or no_host_len == self.length:
			# print("找到真实ip地址")
			self.result.add(ipadress)

	def run(self):
		print("[+] phpinfo测试...")
		self.check_phpinfo()
		print("[+] 奇特ping测试...")
		self.special_ping()
		print("[+] DNS解析历史记录...")
		# self.domain_history()
		print("[+] 子域名扫描...")
		self.subscan()
		'''
		while len(self.ips) != 0:
			target = self.ips.pop()
			print(target)
		'''
		while len(self.ips) != 0:
			target = self.ips.pop()
			cidr = IPy.IP(target).make_net('255.255.255.0')
			if not cidr in self.cidr_set:
				self.cidr_set.add(cidr)

		# 		for cidr in self.cidr_set:
		while len(self.cidr_set) != 0:
			cidr = self.cidr_set.pop()
			# 将每一个C段展开后放到列表里
			print("[+] 扫描C段: {}".format(cidr))
			temp_list = []
			# print(type(cidr))
			for ip in cidr:
				target = str(self.scheme) + "://" + str(ip) + ":" + str(self.port)
				temp_list.append(target)

			# 多线程
			pools = 20
			pool = ThreadPool(pools)
			pool.map(self.Cscan, temp_list)
			pool.close()
			pool.join()

		if len(self.result) != 0:
			print("[+] 找到可能的IP地址")
			while len(self.result) != 0:
				print(self.result.pop())
		else:
			print("[-] 没有找到可能的ip地址")




def main():
	if len(sys.argv) < 2:
		print("Usage: python3 scan.py http://domain.com")
		return
	else:
		target = sys.argv[1]

	parse = urlparse(target)
	netloc = str(parse.netloc)
	name = get_cdn(netloc).run()
	if name != "no cdn":
		print("[+] 目标存在CDN: " + name)
		bypass_cdn(target=target).run()

	else:
		print("[+] 目标不存在CDN")
		# print(bypass_cdn(target=target).check_phpinfo())
		print("[+] " + bypass_cdn(target=target).get_ip())


if __name__ == '__main__':
	main()
