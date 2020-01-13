# /**
#  * @author Yiwei Li
#   Version: 0.5 change to collect (time, originator, querier) tuple
#            0.4 multithreading support
#            0.3 iterate all filename_suffix
#            0.2 collects ipv6 originator
#            0.1 collects request ip record from all PTR req
#  * @email liyw19@mails.tsinghua.edu.cn
#  * @create date 2019-12-07 19:26:18
#  * @modify date 2019-12-18 20:14:56
#  * @desc This program would parse a bunch of DNS pcap traces and convert any IPv6 PTR record into (timestamp, originator, querier) tuple.
#  */

import pyparsing as pp
import sys, os
from multiprocessing import Process, Value, Pool

time = pp.Word(pp.nums + '.:')

req_id_suffix = pp.Literal('+%').suppress() | pp.Literal('%').suppress() | pp.Literal('+').suppress()
req_id = pp.Word(pp.nums) + pp.Optional(req_id_suffix)
req_domain_name = pp.Word(pp.printables)
req_extra_arg = pp.Literal(r'[1au]').suppress() | pp.Literal(r'[b2&3=0x500]').suppress()
addrportv6 = pp.Word(pp.printables)
response_pkt_cnt = pp.Word(pp.printables)
response_id_suffix = pp.Word(pp.printables)
dns_req_type = pp.Literal('A?') | pp.Literal('AAAA?') | pp.Literal('PTR?') | pp.Literal('DNSKEY?') | pp.Literal('DS?') | pp.Literal('NS?') | pp.Literal('SOA?') | pp.Literal('SRV?') | pp.Literal('MX?') | pp.Literal('CNAME?') | pp.Literal('TXT?') | pp.Literal('ANY?') | pp.Literal('SPF?')

grammarv6_req = time.setResultsName("req_time") + pp.Literal('IP6').suppress() + addrportv6.setResultsName("req_src") + pp.Literal('>').suppress() + addrportv6 + req_id + pp.Optional(req_extra_arg) + dns_req_type.setResultsName("req_type") + req_domain_name.setResultsName("req_domain_name")
grammarv6_response = time + pp.Literal('IP6').suppress() + addrportv6 + pp.Literal('>').suppress() + addrportv6 + req_id + response_id_suffix + response_pkt_cnt

max_proc = 4 # paralleled processes it uses

def form_v6addr_from_list(lst):
    # reverse ipv6 address from PTR record
    if len(lst) != 32:
        return
    ret = ''
    for i in range(0, 8):
        ret = ret + ''.join(lst[4 * i: 4 * i + 4])
        if (i != 7):
            ret = ret + ':'
    return ret

def convert_and_parse(proc_id):
    parse_id = 0
    req_cnt = 0
    parsed_cnt = 0
    convert_cnt = 0
    ipv4_ptr_num = 0
    ipv6_ptr_num = 0

    output_filename = sys.argv[3]
    f_output = open(output_filename + "_" + str(proc_id), "w+")
    for filename in os.listdir(sys.argv[1]):
        if filename.startswith(sys.argv[2]):
            convert_cnt = convert_cnt + 1
            if (convert_cnt % max_proc != proc_id):
                continue # only handle file that belongs to this thread

            trace_filename = sys.argv[1] + '/' + filename
            print("[" + str(proc_id) + "] convert file " + trace_filename)
            os.system("tcpdump -ns 0 -r " + trace_filename + " > " + "./trace" + str(proc_id) + ".in")
            print("[" + str(proc_id) + "] parse file " + trace_filename)
            with open("./trace" + str(proc_id) + ".in", 'r') as lines:
                for line in lines:
                    if '?' in line:
                        # DNS request
                        try:
                            parsed_req = grammarv6_req.parseString(line)
                            # print(parsed_req)
                            parse_id = parse_id + 1
                            if not '.' in parsed_req.req_src:
                                continue

                            p_req_ipv6addr = parsed_req.req_src.index('.')
                            req_ipv6addr = parsed_req.req_src[0:p_req_ipv6addr] # this querier
                            if (parsed_req.req_type == "PTR?"):
                                req_cnt = req_cnt + 1
                                if not 'lan' in parsed_req.req_domain_name: # private ip addrs are ignored
                                    req_rdns_ip = parsed_req.req_domain_name # this originator
                                    req_time = parsed_req.req_time # this timestamp
                                    if '.in-addr.arpa.' in req_rdns_ip:
                                        # IPv4 PTR record
                                        ipv4_ptr_num = ipv4_ptr_num + 1
                                        req_rdns_ip = parsed_req.req_domain_name.replace('.in-addr.arpa.', '').strip()
                                    elif '.ip6.arpa.' in req_rdns_ip:
                                        # IPv6 PTR record
                                        ipv6_ptr_num = ipv6_ptr_num + 1
                                        req_rdns_ip = req_rdns_ip.replace('.ip6.arpa.', '').strip()
                                        tmp_ip_list = req_rdns_ip.split('.')[::-1]

                                        req_rdns_ip = form_v6addr_from_list(tmp_ip_list)
                                        parsed_cnt = parsed_cnt + 1
                                        if (parsed_cnt == 10000):
                                            print('[' + str(proc_id) + '] 10000 alive report. ', req_ipv6addr, ' reports originator:', req_rdns_ip)
                                            parsed_cnt = 0

                                        # print("%s\t%s\t%s" % (req_time, req_rdns_ip, req_ipv6addr))
                                        f_output.write("%s\t%s\t%s\n" % (req_time, req_rdns_ip, req_ipv6addr))

                        except pp.ParseException:
                            pass
                    else:
                        # DNS Response, ignored now
                        pass
                        # try:
                        #     parsed_response = grammarv6_response.parseString(line)
                        #     # print (parsed_response)
                        # except pp.ParseException:
                        #     pass

    print('total DNS requests: ', parse_id)
    print('total ipv6 PTR requests:', ipv6_ptr_num)
    print('total ipv4 PTR requests:', ipv4_ptr_num)


if __name__ == "__main__":
    if (len(sys.argv) < 4):
        print("Usage: python3 preprocessing.py trace_folder trace_file_prefix out_file")
        sys.exit(0)

    p = []
    for proc_i in range(0, max_proc):
        p_i = Process(target=convert_and_parse, args=(proc_i,))
        p_i.start()
        p.append(p_i)

    for proc_i in range(0, max_proc):
        p[proc_i].join()

