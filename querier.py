# /**
#  * @author Yiwei Li
#  * @email liyw19@mails.tsinghua.edu
#  * @create date 2020-01-09 20:18:37
#  * @modify date 2020-01-10 13:05:34
#   This program would load trace files and generate querier type info. This program infer querier type using domain keyword matching and AS matching. Note that all domain info (ipmeta) can be reused.
#  */

import sys
import os
from ipwhois import IPWhois, exceptions
from enum import Enum
import json
import subprocess

QuerierType = Enum('QuerierType', ('MajorService', 'Home', 'DNS', 'Mail', 'CDN', 'Firewall', 'Antispam', 'Cernet', 'Unknown'))

dic_querier = {}
dic_ip = {}

recorded_ipmeta = 0
total_ipmeta = 0

class Querier(object):
    list_originator = []
    total_unique_originators = 0
    total_requests = 0
    as_num = -1
    as_description = ''
    domain = ''
    ipaddr = ''
    querier_type = QuerierType.Unknown

def safe_int(val):
    try:
        variable = int(val)
    except ValueError:
        variable = 0
    return variable

def lookup_ip(ipaddr):
    global recorded_ipmeta, total_ipmeta
    if not ipaddr in dic_ip:
        dic_ip[ipaddr] = {}
        dic_ip[ipaddr]['as_description'] = ''
        dic_ip[ipaddr]['as_id'] = ''
        dic_ip[ipaddr]['as_country_code'] = ''
        dic_ip[ipaddr]['domain'] = ''
        total_ipmeta = total_ipmeta + 1
        try:
            obj = IPWhois(str(ipaddr), timeout = 1)
            results = obj.lookup_rdap(depth = 1, rate_limit_timeout = 60)
            dic_ip[ipaddr]['as_description'] = str(results['asn_description']).strip()
            dic_ip[ipaddr]['as_id'] = str(results['asn']).strip()
            dic_ip[ipaddr]['as_country_code'] = str(results['asn_country_code']).strip()
            completed_proc = subprocess.run(['host', '-W', '1', str(ipaddr)], stdout=subprocess.PIPE)
            domain_res = str(completed_proc.stdout.decode('utf-8')).rstrip().lower()
            # print(domain_res)
            if 'not found' in domain_res or 'timed out' in domain_res or 'no PTR record' in domain_res:
                dic_ip[ipaddr]['domain'] = 'unknown'
            else:
                dic_ip[ipaddr]['domain'] = domain_res.split(' ')[-1]
                recorded_ipmeta = recorded_ipmeta + 1
        except Exception:
            dic_ip[ipaddr]['as_description'] = ''
            dic_ip[ipaddr]['as_id'] = ''
            if (dic_ip[ipaddr]['domain'] == ''):
                dic_ip[ipaddr]['domain'] = 'unknown'
        # cache ipmeta
        if (len(dic_ip) % 30 == 0):
            print('[cached ip_meta] recorded ratio=%d/%d' % (recorded_ipmeta, len(dic_ip)))
            ipinfo_file = open('./ipmeta.txt', 'w')
            ipinfo_dump = json.dumps(dic_ip)
            ipinfo_file.write(ipinfo_dump)
            ipinfo_file.close()
    return dic_ip[ipaddr]

def infer_querier_type(querier):
    dic_domain_keyword_pattern = {
        'mail': ['hinet', 'mail', 'mx', 'smtp', 'post', 'correo', 'poczta', 'send', 'lists', 'newsletter', 'zimbra', 'mta', 'pop', 'imap'], # hinet: a taiwan mail server
        'firewall': ['wall', 'fw'],
        'antispam': ['ironport', 'spam'],
        'cdn': ['cdn', 'mip'], # mip: Mobile Instant Pages
        'dns': ['dns', 'resolv', 'name', 'cns', 'ns', 'cache'],
        'home': ['ap', 'cable', 'cpe', 'customer', 'dsl', 'dynamic', 'pop', 'fiber', 'flets', 'home', 'host', 'ip', 'pool', 'retail', 'user'],
        'majorservice': ['www', 'vps', 'tv'],
        'cernet': ['cernet']
    }
    dic_as_pattern = {
        'majorservice': [15169], #15169 Google
        'cdn': [13335], # 13335 CloudFlare
        'cernet': [133111, 23910, 133512, 133513] # 133111 cernet, 23910 CERNET2, 133512 IANA
    }
    for item in dic_domain_keyword_pattern['mail']:
        if item in querier.domain:
            return QuerierType.Mail
    for item in dic_domain_keyword_pattern['firewall']:
        if item in querier.domain:
            return QuerierType.Firewall
    for item in dic_domain_keyword_pattern['antispam']:
        if item in querier.domain:
            return QuerierType.Antispam
    for item in dic_domain_keyword_pattern['cdn']:
        if item in querier.domain:
            return QuerierType.CDN
    for item in dic_as_pattern['cdn']:
        if item == querier.as_num:
            return QuerierType.CDN
    for item in dic_domain_keyword_pattern['dns']:
        if item in querier.domain:
            return QuerierType.DNS
    for item in dic_domain_keyword_pattern['home']:
        if item in querier.domain:
            return QuerierType.Home
    for item in dic_domain_keyword_pattern['majorservice']:
        if item in querier.domain:
            return QuerierType.MajorService
    for item in dic_as_pattern['majorservice']:
        if item == querier.as_num:
            return QuerierType.MajorService
    for item in dic_domain_keyword_pattern['cernet']:
        if item in querier.domain:
            return QuerierType.Cernet
    for item in dic_as_pattern['cernet']:
        if item == querier.as_num:
            return QuerierType.Cernet
    if (querier.domain != 'unknown' and querier.domain != ''):
        print(querier.domain)
    return QuerierType.Unknown

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: %s trace.in querier.json" % (sys.argv[0]))
        # format of trace file: (timestamp, originator, querier)
        sys.exit(0)

    # read asnum_list
    with open('./ipmeta.txt', 'r') as f:
        js = f.read()
        try:
            dic_ip = json.loads(js)
        except json.decoder.JSONDecodeError:
            print('Error: JsonDecode Error')
            dic_ip = {}

    file = open(sys.argv[1], 'r')
    for line in file:
        line_arr = line.split('\t')
        originator = line_arr[1]
        querier = line_arr[2].rstrip()
        if not querier in dic_querier:
            dic_querier[querier] = Querier()
            dic_querier[querier].ipaddr = querier
            dic_querier[querier].total_unique_originators = 0
            dic_querier[querier].list_originator = []
        if not originator in dic_querier[querier].list_originator:
            dic_querier[querier].list_originator.append(originator)
            dic_querier[querier].total_unique_originators = dic_querier[querier].total_unique_originators + 1
        dic_querier[querier].total_requests = dic_querier[querier].total_requests + 1
    file.close()
    print("Step1 finish loading traces")

    # total_known_queriers = 0
    # querier_cnt = 0
    # for querier in dic_querier.values():
    #     if querier.total_unique_originators >= 10:
    #         querier_cnt = querier_cnt + 1
    for querier in dic_querier.values():
        ip_info = lookup_ip(querier.ipaddr)
        querier.as_num = safe_int(ip_info['as_id'])
        querier.domain = ip_info['domain']
        querier.as_description = ip_info['as_description']
        querier.querier_type = infer_querier_type(querier)
        # if (querier.querier_type != QuerierType.Unknown):
            # total_known_queriers = total_known_queriers + 1
            # print(total_known_queriers, querier_cnt, ':', querier.ipaddr, querier.total_unique_originators, querier.as_num, querier.domain, '->', querier.querier_type)

    print("Step2 finish looking up ipmeta")

    dic_dump_q = {}
    for ip in dic_querier:
        querier = dic_querier[ip]
        if querier.querier_type == QuerierType.Unknown:
            continue
        dic_dump_q[ip] = {}
        dic_dump_q[ip]['type'] = querier.querier_type.value
        dic_dump_q[ip]['asn_id'] = dic_ip[ip]['as_id']
        dic_dump_q[ip]['asn_country_code'] = dic_ip[ip]['as_country_code']
        dic_dump_q[ip]['requests'] = querier.total_requests

    out_file = open(sys.argv[2], 'w+')
    querier_dump = json.dumps(dic_dump_q)
    out_file.write(querier_dump)
    out_file.close()

    # cache ipmeta
    ipinfo_file = open('./ipmeta.txt', 'w')
    ipinfo_dump = json.dumps(dic_ip)
    ipinfo_file.write(ipinfo_dump)
    ipinfo_file.close()
    print("Step3 finish dumping sorted queriers")

