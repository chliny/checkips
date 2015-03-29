#!/usr/bin/env python3
#-*- coding=utf-8 -*-

import fnmatch
import logging
import pickle

from checkips import CheckHosts
from getips import GetIps

class FixCheckIps(CheckHosts):
    def __init__(self, fix_name_list, find_new_ip=False):
        super(FixCheckIps, self).__init__()
        self.fix_hosts_file = "/etc/hosts"
        self.old_domain_dict = self.getHosts2Dict([self.fix_hosts_file])
        self.find_new_ip = find_new_ip
        for name, ip_list in list(self.old_domain_dict.items()):
            self.old_domain_dict[name] = ip_list[0]


        if fix_name_list:
            self.fix_name_list = fix_name_list
            new_ip_dict = self.getIpDict()

            if self.find_new_ip:
                self.dumpDict2Pickle(self.ip_dict,self.ip_pck,need_clear=True)
                self.dumpDict2Pickle(self.domain_dict,self.domain_pck,need_clear=True)

            self.ip_dict = new_ip_dict
            self.domain_dict = self.old_domain_dict

    def getIpDict(self):
        new_ip_dict = {}

        for fix_name in self.fix_name_list:
            match_list = fnmatch.filter(list(self.raw_hosts_dict.keys()),fix_name)
            for matchname in match_list:
                if self.globMach(self.black_host_list, matchname):
                   continue
                self.old_domain_dict[matchname] = ""
                ip_list = []
                if matchname in self.domain_ip_dict:
                    ip_list.extend(self.domain_ip_dict[matchname])
                if matchname in self.raw_hosts_dict:
                    ip_list.extend(self.raw_hosts_dict[matchname])
                ip_list = list(set(ip_list))
                for ip in ip_list:
                    if ip not in new_ip_dict:
                        new_ip_dict[ip] = 0
                    if ip not in self.ip_dict:
                       self.ip_dict[ip] = 0
                       self.find_new_ip = True


                if self.find_new_ip or not ip_list:
                    self.find_new_ip = False
                    new_ip_list = self.get.get_ips(matchname)
                    for ip in new_ip_list:
                        if ip not in self.ip_dict:
                            self.ip_dict[ip] = 0
                            self.find_new_ip = True
                        if ip not in new_ip_dict:
                            new_ip_dict[ip] = 0

            if not match_list: 
                self.old_domain_dict[fix_name] = ""
                if fix_name not in self.domain_dict:
                    self.domain_dict[fix_name] = ""
                    self.find_new_ip = True

                new_ip_list = self.get.get_ips(fix_name)
                for ip in new_ip_list:
                    if ip not in self.ip_dict:
                        self.ip_dict[ip] = 0
                    if ip not in new_ip_dict:
                        new_ip_dict[ip] = 0
                        self.find_new_ip = True

        return new_ip_dict

    
    def all_check(self):
        self.fix_name_list = self.old_domain_dict.keys()
        new_ip_dict = self.getIpDict()

        if self.find_new_ip:
            self.dumpDict2Pickle(self.ip_dict,self.ip_pck,need_clear=True)
            self.dumpDict2Pickle(self.domain_dict,self.domain_pck,need_clear=True)

        self.ip_dict = new_ip_dict
        self.domain_dict = self.old_domain_dict
        self.check() 

def get_group(group_list):
    group_map ={
        "google_cdn":[
            "*.googleapis.com",
            "*.ggpht.com",
            "*.googleusercontent.com",
            "*.gstatic.com",
            "*.ytimg.com",
            ],
        "google_spot":[
            "*.blogspot.com",
            "blogspot.com",
            "*.blogblog.com",
            "blogblog.com",
            "*.blogger.com",
            "blogger.com",
            "*.appspot.com",
            "appspot.com"
            ],

        "google_com":[
            "goo.gl",
            "*.googlecode.com",
            "*.google.com",
            "google.com",
            "google.com.*",
            "*.google.com.*",
            "*.google.cn",
            "gmail.com",
            "*.gmail.com",
            "*.android.com",
            ],
        "dropbox":[
            "*.dropbox.com",
            "dropbox.com",
            "*.dropboxstatic.com",
            "dropboxstatic.com",
            ],
        "wordpress":[
            "*.wordpress.com",
            "*.wp.com",
            ],
        "ingress":[
            "m-dot-betaspike.appspot.com",
            "betaspike.appspot.com",
            "lfe-alpo-gm.appspot.com",
            "www.ingress.com",
            ],
        "twitter":[
            "twitter.com",
            "*.twitter.com",
            "*.twimg.com",
            "t.co",
            "*.t.co",
            ],
        "facebook":[
            "facebook.com",
            "*.facebook.com",
            "*.akamaihd.net",
            "*.fbcdn.net",
            ],
        "instagram":[
            "*.instagram.com",
            "instagram.com",
            "*.cdninstagram.com",
            "cdninstagram.com",
            ],
        "wiki":[
                
            "*.wikipedia.org",
            "wikipedia.org",
            "wikimedia.org",
            "*.wikidata.org",
            "wikidata.org",
            "*.wikisource.org",
            "wikisource.org",
            "wikiquote.org",
            "*.wikiquote.org",
            "wikivoyage.org",
            "*.wikivoyage.org",
        ],
    }
    ret_list =[]
    for groupname in group_list:
        if groupname in group_map:
            ret_list.extend(group_map[groupname])
    return ret_list

if __name__ == "__main__":
    fix_name_list = get_group(["google_com"])
    #fix_name_list = [""]

    fix = FixCheckIps(fix_name_list, find_new_ip=False)
    fix.check()
