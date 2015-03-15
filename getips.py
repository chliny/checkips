#!/usr/bin/env python3
#-*- coding=utf-8 -*-

import requests
import concurrent.futures
import re
import sys
import time
import json
import logging

class GetIps:
    def __init__(self,logging):
        self.proxies = {
            "http": "http://127.0.0.1:8087",
            "https" : "http://127.0.0.1:8087",
        }
        self.ip_pattern = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
        self.logging = logging

    def get_chinaz(self, name, timeout):
        name = name.strip()
        session = requests.Session()
        ips = []

        url = "http://ping.chinaz.com"
        playload ={
           "alllinetype" : "全选",
           "host" : "google.com",
           "linetype" : "电信",
           "linetype" : "多线",
           "linetype" : "联通",
           "linetype" : "移动",
           "linetype" : "海外",
        }
        try:
            r = session.post(url, data=playload, proxies=self.proxies, timeout=timeout)
            m = re.search(r'src=\'(/iframe\.ashx.+)\'', r.text)

            url = url + m.group(1)
            r = session.get(url, proxies=self.proxies,timeout=10)
            ips = self.ip_pattern.findall(r.text)
        except Exception as e:
            self.logging.debug("name:%s:%s" % (name,e))

        ips = list(set(ips))
        ips = [str(ip) for ip in ips if ip != "127.0.0.1"]
        return ips

    def get_ping_eu(self,name,timeout):
        name = name.strip()
        session = requests.Session()
        ips = []
        
        url = "http://ping.eu/action.php?atype=3"
        playload = {
            "go" : "GO",
            "host" : name,
        }
        try:
            r = session.post(url, data=playload, proxies=self.proxies, timeout=timeout)
            ips = self.ip_pattern.findall(r.text)
        except Exception as e:
            self.logging.debug("name:%s:%s" % (name,e))

        ips = list(set(ips))
        ips = [str(ip) for ip in ips if ip != "127.0.0.1"]
        return ips

    def get_ultratools(self,name,timeout):
        name = name.strip()
        session = requests.Session()
        ips = []

        url = "https://www.ultratools.com/tools/dnsLookupResult"
        playload = {
            "domain" : name,
        }
        try:
            r = session.post(url, data=playload, timeout=timeout)
            ips = self.ip_pattern.findall(r.text)
        except Exception as e:
            self.logging.debug("name:%s:%s" % (name,e))

        ips = list(set(ips))
        ips = [str(ip) for ip in ips if ip != "127.0.0.1"]

        return ips

    def get_ips(self,name):
        ips = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_list = []
            future_list.append(executor.submit(self.get_chinaz, name,5.0))
            future_list.append(executor.submit(self.get_ping_eu, name,3.0))
            future_list.append(executor.submit(self.get_ultratools, name,3.0))
            for future in future_list:
                ips.extend(future.result())

        ips = list(set(ips))
        return ips


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=0,\
                format="[%(asctime)s]: %(levelname)s: %(funcName)s %(message)s")
    get = GetIps(logging)
    print( get.get_ips("talkgadget.google.com"))
