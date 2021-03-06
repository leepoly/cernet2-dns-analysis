# /**
#  * @author Yiwei Li
#  * @email liyw19@mails.tsinghua.edu
#  * @create date 2020-01-09 20:18:37
#  * @modify date 2020-01-12 20:24:15
#  * @desc Just a dirty python for statistics.
#  */

import sys
import os
from ipwhois import IPWhois, exceptions
from enum import Enum
import json
import subprocess
import time
from datetime import datetime
from ipaddress import ip_interface as ipaddr

OriginatorType = Enum('OriginatorType', ('MajorService', 'Ad-tracker', 'DNS', 'Mail', 'Web', 'Tor', 'Tunnel', 'Router', 'CDN', 'NTP', 'Scan', 'Spam', 'Cernet', 'Unknown'))

dic_ip = {}
dic_ori = {} # dic_originator

recorded_ipmeta = 0
total_ipmeta = 0

Active_Originator_Threshold = 20
Querier_Type_Length = 10

class Originator(object):
    list_queriers = {}
    total_unique_queriers = 0 # request frequency
    total_requests = 0
    total_unique_querier_as = 0 #U
    total_unique_querier_country = 0 #U
    total_querier_requests = 0 #U all requests of querier it related, for querier popularity
    querier_ip_prefix_entropy = 0 #U
    active_period_start = 0 # request persistency
    active_period_end = 0 # request persistency
    active_period_persistence = 0.0 # request persistency

    querier_type_vec = [0] * Querier_Type_Length
    querier_as_vec = [] #U
    querier_country = [] #U
    querier_popularity = [] #U

    as_num = -1
    domain = ''
    ipaddr = ''
    as_country_code = ''
    originator_type = OriginatorType.Unknown

def safe_int(val):
    try:
        variable = int(val)
    except ValueError:
        variable = 0
    return variable

def stat_querier_type(originator):
    type_vec = [0] * Querier_Type_Length
    total_cnt = 0
    for querier_ip in originator.list_queriers:
        if querier_ip in dic_querier:
            type_id = dic_querier[querier_ip]['type']
            access_num = originator.list_queriers[querier_ip]
            type_vec[type_id] = type_vec[type_id] + access_num
            total_cnt = total_cnt + access_num
    if total_cnt > 0:
        type_vec = [1.0*item / total_cnt for item in type_vec]
    return type_vec

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
            ipinfo_file = open('./cli_ipinfo.txt', 'w')
            ipinfo_dump = json.dumps(dic_ip)
            ipinfo_file.write(ipinfo_dump)
            ipinfo_file.close()
    return dic_ip[ipaddr]

def infer_originator_type(originator):
    dic_domain_keyword_pattern = {
        'mail': ['hinet', 'mail', 'mx', 'smtp', 'post', 'correo', 'poczta', 'send', 'lists', 'newsletter', 'zimbra', 'mta', 'pop', 'imap'], # hinet: a taiwan mail server
        'firewall': ['wall', 'fw'],
        'antispam': ['ironport', 'spam'],
        'cdn': ['cdn', 'mip'], # mip: Mobile Instant Pages
        'dns': ['dns', 'resolv', 'name', 'cns', 'ns', 'cache'],
        'home': ['ap', 'cable', 'cpe', 'customer', 'dsl', 'dynamic', 'pop', 'fiber', 'flets', 'home', 'host', 'ip', 'pool', 'retail', 'user'],
        'majorservice': ['www', 'vps', 'cloud'],
        'cernet': ['cernet'],
        'ntp': ['ntp', 'time'],
        'web': ['www'],
        'tunnel': ['tunnel'],
        'tor': ['tor']
    }
    dic_as_pattern = {
        'majorservice': [15169], #15169 Google 13335 CloudFlare
        'cdn': [13335],
        'cernet': [133111, 23910, 133512, 133513] # 133111 cernet, 23910 CERNET2, 133512 IANA
    }
    dic_ipaddr_pattern = {
        'tunnel': ['2001::/32', '2002::/16'],
        'majorservice': ['2607:f8b0::/16'], # google network
        'lan': ['ffff::/4'] # lan
    }
    for item in dic_domain_keyword_pattern['mail']:
        if item in originator.domain:
            return OriginatorType.Mail
    for item in dic_domain_keyword_pattern['cdn']:
        if item in originator.domain:
            return OriginatorType.CDN
    for item in dic_as_pattern['cdn']:
        if item == originator.as_num:
            return OriginatorType.CDN
    for item in dic_domain_keyword_pattern['dns']:
        if item in originator.domain:
            return OriginatorType.DNS
    for item in dic_domain_keyword_pattern['majorservice']:
        if item in originator.domain:
            return OriginatorType.MajorService
    for item in dic_as_pattern['majorservice']:
        if item == originator.as_num:
            return OriginatorType.MajorService
    for item in dic_ipaddr_pattern['majorservice']:
        if ipaddr(originator.ipaddr).ip in ipaddr(item).network:
            return OriginatorType.MajorService
    for item in dic_domain_keyword_pattern['ntp']:
        if item in originator.domain:
            return OriginatorType.NTP
    for item in dic_domain_keyword_pattern['web']:
        if item in originator.domain:
            return OriginatorType.Web
    for item in dic_domain_keyword_pattern['tor']:
        if item in originator.domain:
            return OriginatorType.Tor
    for item in dic_domain_keyword_pattern['tunnel']:
        if item in originator.domain:
            return OriginatorType.Tunnel
    for item in dic_ipaddr_pattern['tunnel']:
        if ipaddr(originator.ipaddr).ip in ipaddr(item).network:
            return OriginatorType.Tunnel
    for item in dic_domain_keyword_pattern['cernet']:
        if item in originator.domain:
            return OriginatorType.Cernet
    for item in dic_as_pattern['cernet']:
        if item == originator.as_num:
            return OriginatorType.Cernet
    if (originator.domain != 'unknown' and originator.domain != ''):
        print('[unknown type report]', originator.domain)
    return OriginatorType.Unknown

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: %s trace.in sort.out querier.in" % (sys.argv[0]))
        sys.exit(0)

    # read querier list
    with open(sys.argv[3], 'r') as f:
        js = f.read()
        try:
            dic_querier = json.loads(js)
        except json.decoder.JSONDecodeError:
            print('Error: JsonDecode Error')
            dic_querier = {}

    # read asnum_list
    with open('./cli_ipinfo.txt', 'r') as f:
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
        # print(line)
        try:
            req_time = datetime.strptime(line_arr[0], '%H:%M:%S.%f')
        except ValueError:
            continue

        if not originator in dic_ori:
            dic_ori[originator] = Originator()
            dic_ori[originator].ipaddr = querier
            dic_ori[originator].total_unique_queriers = 0
            dic_ori[originator].total_requests = 0
            dic_ori[originator].list_queriers = {}
            dic_ori[originator].querier_type_vec = []
            dic_ori[originator].querier_as_vec = []
            dic_ori[originator].querier_country = []
            dic_ori[originator].querier_popularity = []

        if not querier in dic_ori[originator].list_queriers:
            dic_ori[originator].list_queriers[querier] = 0
            dic_ori[originator].total_unique_queriers = dic_ori[originator].total_unique_queriers + 1
        dic_ori[originator].list_queriers[querier] = dic_ori[originator].list_queriers[querier] + 1
        dic_ori[originator].total_requests = dic_ori[originator].total_requests + 1

        if dic_ori[originator].active_period_start == 0 or dic_ori[originator].active_period_start > req_time:
            dic_ori[originator].active_period_start = req_time
        if dic_ori[originator].active_period_end == 0 or dic_ori[originator].active_period_end < req_time:
            dic_ori[originator].active_period_end = req_time
    file.close()
    print("Step1 finish loading files")

    requests_cnt = {}
    requests_cnt_10 = {}
    requests_cnt_100 = {}
    requests_cnt_1000 = {}
    for item in OriginatorType:
        requests_cnt[str(item)] = 0
        requests_cnt_10[str(item)] = 0
        requests_cnt_100[str(item)] = 0
        requests_cnt_1000[str(item)] = 0

    for originator in dic_ori.values():
        ori = originator
        if originator.total_unique_queriers < Active_Originator_Threshold: # only interested in ori with over 20 total_requests
            continue
        ip_info = lookup_ip(originator.ipaddr)
        originator.as_num = safe_int(ip_info['as_id'])
        originator.domain = ip_info['domain']
        originator.as_country_code = ip_info['as_country_code']
        originator.originator_type = infer_originator_type(originator)
        originator.querier_type_vec = stat_querier_type(originator)

        persist_long = (originator.active_period_end - originator.active_period_start).seconds
        if persist_long > 0:
            originator.active_period_persistence = 1.0 * persist_long / originator.total_requests
        else:
            originator.active_period_persistence = -1
        # if originator.originator_type == OriginatorType.Unknown:
            # ori = originator
            # print("%s\t%d\t%d\t%s\t%.2f -> %s" % (ori.ipaddr, ori.total_requests, ori.total_unique_queriers, ori.as_num, ori.active_period_persistence, ori.querier_type_vec))
        requests_cnt[str(ori.originator_type)] = requests_cnt[str(ori.originator_type)] + ori.total_requests

    print("Step2 finish looking up ipmeta")

    sorted_dic = sorted(dic_ori.items(), key=lambda item:item[1].total_requests / item[1].total_unique_queriers, reverse = True)
    out_file = open(sys.argv[2], 'w+')

    cnt = 0
    req_cnt = 0
    querier_cnt = 0

    for originator in sorted_dic:
        ori = originator[1]
        if ori.total_unique_queriers < Active_Originator_Threshold: # only interested in ori with over 20 total_requests
            continue
        cnt = cnt + 1
        req_cnt = req_cnt + ori.total_requests
        querier_cnt = querier_cnt + ori.total_unique_queriers
        if cnt < 10:
            print("%s\t%d\t%d\t%s\t%.2f -> %s" % (ori.ipaddr, ori.total_requests, ori.total_unique_queriers, ori.as_num, ori.active_period_persistence, ori.originator_type))
            requests_cnt_10[str(ori.originator_type)] = requests_cnt_10[str(ori.originator_type)] + ori.total_requests
        if cnt < 100:
            requests_cnt_100[str(ori.originator_type)] = requests_cnt_100[str(ori.originator_type)] + ori.total_requests
        if cnt < 1000:
            requests_cnt_1000[str(ori.originator_type)] = requests_cnt_1000[str(ori.originator_type)] + ori.total_requests

    out_file.write('all requests\n')
    print(cnt)
    print(querier_cnt)
    print(req_cnt)
    for key in requests_cnt:
        print(key, requests_cnt[key])
        out_file.write("%s\t%s\n" % (key, requests_cnt[key]))

    out_file.write('top 10 requests\n')
    for key in requests_cnt:
        # print(key, requests_cnt_10[key])
        out_file.write("%s\t%s\n" % (key, requests_cnt_10[key]))
    out_file.write('top 100 requests\n')
    for key in requests_cnt:
        # print(key, requests_cnt_100[key])
        out_file.write("%s\t%s\n" % (key, requests_cnt_100[key]))
    # print('top 1000 requests')
    out_file.write('top 1000 requests\n')
    for key in requests_cnt:
        # print(key, requests_cnt_1000[key])
        out_file.write("%s\t%s\n" % (key, requests_cnt_1000[key]))

    file_cdf = open('./cdf.txt', 'w+')
    max_unique_queriers = 0
    for originator in sorted_dic:
        ori = originator[1]
        if ori.total_unique_queriers > max_unique_queriers:
            max_unique_queriers = ori.total_unique_queriers
    cdf_i = [0] * (max_unique_queriers + 1)
    cdf_unique_querier = [0] * (max_unique_queriers + 1)
    for originator in sorted_dic:
        ori = originator[1]
        cdf_i[ori.total_unique_queriers] = cdf_i[ori.total_unique_queriers] + 1
        cdf_unique_querier[ori.total_unique_queriers] = cdf_unique_querier[ori.total_unique_queriers] + ori.total_requests

    for i in range(1, len(cdf_i)):
        # cdf_i[i] = cdf_i[i - 1] + cdf_i[i]
        # cdf_unique_querier[i] = cdf_unique_querier[i-1] + cdf_unique_querier[i]
        if cdf_i[i] == 0:
            val = 0
        else:
            val = 1.0 * cdf_unique_querier[i] / cdf_i[i]
        file_cdf.write("%d\t%.4f\n" % (i, val))
    file_cdf.close()

    for originator in sorted_dic:
        ori = originator[1]
        if ori.total_unique_queriers < Active_Originator_Threshold: # only interested in ori with over 20 total_requests
            continue
        # print("%s\t%d\t%d\t%s\t%.2f -> %s" % (ori.ipaddr, ori.total_requests, ori.total_unique_queriers, ori.as_num, ori.active_period_persistence, ori.originator_type))
        out_file.write("%s\t%d\t%d\t%s\t%.2f -> %s\n" % (ori.ipaddr, ori.total_requests, ori.total_unique_queriers, ori.as_num, ori.active_period_persistence, ori.originator_type))
    out_file.close()

    ipinfo_file = open('./cli_ipinfo.txt', 'w')
    ipinfo_dump = json.dumps(dic_ip)
    ipinfo_file.write(ipinfo_dump)
    ipinfo_file.close()

