cernet2-dns-analysis
===

A python project for analyzing DNS backscatter footprint in CERNET2

This work extracts DNS PTR records and analyzes valuable originators and queries from those records. It can infer originators' type via their AS number and domain keyword. For those unknown types, it collects correleted querier info and generates a querier feature vector for future clustering. We have detected several originator clusters from their accessing behaviours.

More information is in this report: `NGI_proj.pdf`

Usage
---
You need pcap trace files to start analyzing.

`python3 preprocessing.py trace_folder_path trace_in_prefix list_out_prefix` 

Preprocessing parses pcap traces from files that has such prefix and is in that folder. This program generates a (T, O, Q) list each thread. You need combine those list manually.

`python3 querier.py list.in list.querier.json`

querier.py would infer querier type to generate feature vector.

Note that domain and AS meta info will be recorded for reusingi in `ipmeta.txt`.

`python3 originator.py list.in list.originator.unknown.json list.querier.json`

originator.py would generate unknown originators with their correlated queriers' type vector. It also do originator type inference by adjusting the code.

In `cluster.ipynb`, I made a naive clustering from `list.originator.unknown.json` using K-Means. 

Contact me if you found bugs: liyw19@mails.tsighua.edu.cn

Yiwei Li
