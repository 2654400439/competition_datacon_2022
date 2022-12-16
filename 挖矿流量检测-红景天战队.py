# coding = utf-8
import os,sys
import numpy as np
import random
from scapy.all import *
import collections
from tabulate import tabulate
from tqdm import tqdm

import requests
import time
import random
from tqdm import trange

import sklearn
from sklearn.decomposition import * 
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import *
from imblearn.over_sampling import SMOTE, SMOTEN, SMOTENC
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import BernoulliNB

from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, VotingClassifier
from sklearn.metrics import recall_score, f1_score, accuracy_score, confusion_matrix

import joblib
import pickle
def writeBunchobj(path, obj):
    file = open(path, 'wb')
    pickle.dump(obj, file)
    file.close()
    return
def readBunchobj(path):
    file_obj = open(path, 'rb')
    bunch = pickle.load(file_obj)
    file_obj.close()
    return bunch

# rules
def rule1_bytes(data, duration=1000, bytes_range=(40, 120)):
    """ 通信持续时间在 duration，字节大小在 bytes_range 的认为是挖矿流量 """
    res = data['duration']<=duration and bytes_range[0]<=data['min_bytes'] and data['max_bytes']<=bytes_range[1] 
    return res
def rule2_port(data, *args):
    """ 目标端口小于源端口的认为是挖矿流量 """
    res = data["dport"] < data['sport']
    return res
def rule3_ACKPUSH(data, *args):
    """ 将包含ACK&PUSH标志位的认为是挖矿 """
    res = data["ACK&PUSH"] >= 1
    return res
def rule4_FIN(data, *args):
    """ 将不包含 FIN 标志位的认为是挖矿 """
    res = data["FIN"] < 1
    return res
def rule5_RST(data, *args):
    """ 将不包含 RST 标志位的认为是挖矿 """
    res = data["RST"] < 1
    return res

def isMining(data, threshold=4):
    duration=1000
    bytes_range=(40, 120)
    res = 0
    res += rule1_bytes(data, duration, bytes_range)
    res += rule2_port(data)
    res += rule3_ACKPUSH(data)
    res += rule4_FIN(data)
    res += rule5_RST(data)
    return res  

# 分析数据
def get_flow_features(data, id_, pkt):
    """ 更新字典信息 """
    data[id_]['min_bytes'] = min(data[id_]['min_bytes'], pkt.len)
    data[id_]['max_bytes'] = max(data[id_]['max_bytes'], pkt.len)
    data[id_]['duration'] = pkt.time - data[id_]["sta_time"]
    
    data[id_]['pkt_number'] += 1
    data[id_]['pkt_bytes'] += pkt.len
    if pkt.haslayer('TCP'):
        # UGR ACK PSH RST SYN FIN 
        data[id_]["ACK&PUSH"] += (pkt['TCP'].flags & 24) == 24
        data[id_]["FIN"] += (pkt['TCP'].flags & 1) == 1
        data[id_]["RST"] += (pkt['TCP'].flags & 4) == 4
    return
def create_dataset(pcap):
    """ 遍历pcap数据，得到pcap字典数据，字典以会话为key """
    def get_id(pkt):
        id_ = ",".join([pkt['IP'].src, pkt['IP'].dst, str(pkt.sport), str(pkt.dport)])
        id_r = ",".join([pkt['IP'].dst, pkt['IP'].src, str(pkt.dport), str(pkt.sport)])
        if id_ in data: return id_
        if id_r in data: return id_r
        data[id_] = {"src": pkt['IP'].src,
                     "dst": pkt['IP'].dst,
                     "sport": pkt['IP'].sport,
                     "dport": pkt['IP'].dport,
                     "sta_time" : pkt.time,
                     "min_bytes" : 1500000,
                     "max_bytes" : 0,
                     "pkt_number" : 0,
                     "pkt_bytes" : 0,
                     "ACK&PUSH" : 0,
                     "FIN" : 0,
                     "RST" : 0,
                    }
        return id_   
    
    data = {}
    for pkt in pcap:
        id_ = get_id(pkt)
        get_flow_features(data, id_, pkt)
    
    print("Get {} flows".format(len(data)))
    return data 

# 查子域名
def sub_domain2ip_history(sub_domain):
    black_ip_list = []

    url = 'https://site.ip138.com/'+ sub_domain + '/'

    headers = {
       'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36 Edg/100.0.1185.29'
    }

    html = requests.get(url=url, headers=headers).text
    
    try:
        html = html.split('历史解析记录')[1].split('最新域名查询')[0].split('\n')

        for i in range(len(html)):
            if 'class="date">' in html[i]:
                duration = html[i].split('class="date">')[1][:-7]
                start = duration.split('-----')[0]
                end = duration.split('-----')[1]
                start_month, start_day = start.split('-')[1], start.split('-')[2]
                end_month, end_day = end.split('-')[1], end.split('-')[2]
                if int(start_month)*30 + int(start_day) <= 324:
                    if int(end_month)*30 + int(end_day) >= 324:
                        black_ip = html[i+1].split('="_blank">')[1].split('</a>')[0]
                        black_ip_list.append(black_ip)
    except:
        pass                 
    return black_ip_list

# 查域名ip映射
def sub_domain2ip(sub_domain):
    url = 'https://site.ip138.com/domain/read.do?domain=' + sub_domain + '&time=1669969451656'

    headers = {
       'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36 Edg/100.0.1185.29'
    }

    html = requests.get(url=url, headers=headers).text

    html = html.split(',')
    black_ip_list = []
    flag = 0
    for item in html:
        if 'ip' in item:
            black_ip_list.append(item.split(':')[-1][1:-1])
            flag += 1
    print('共添加黑名单ip {} 个，子域名为{}'.format(flag, sub_domain))
    return black_ip_list




if __name__=="__main__":
    pcap_data = rdpcap("cryptomining.pcap")
    data = create_dataset(pcap_data)
    # 保存数据和结果
    writeBunchobj("./pcap_data", pcap_data)
    writeBunchobj("./dict_data", data)
    c = 0
    for d in data:
        res = isMining(data[d])
        
        if res>=4:
            print(c, d, "\t", res)
            c += 1
    print("OK")
    
    # 取比特币前十五、门罗币前十、小狗币前五、以太坊前五
    domain_list = ['foundrydigital.com', 'antpool.com', 'binance.com', 'f2pool.com', 'viabtc.net', 'braiins.com', 'pool.btc.com', 'poolin.com', 'emcd.io', 'sbicrypto.com', 'trustpool.cc', 'ultimuspool.com', 'pega-pool.com', 'titan.io', 'kucoin.com', 'nanopool.org', 'supportxmr.com', 'hashvault.pro', 'c3pool.com', 'p2pool.io', '2miners.com', 'xmrpool.eu', 'moneroocean.stream', 'kryptex.com', 'skypool.org', 'litecoinpool.org', '1pool.org', 'ethermine.org', 'ezil.me', 'hiveon.net']

    for domain in domain_list:
        sub_domain_list = domain2sub_domain(domain)

        black_ip_list = []
        for i in trange(len(sub_domain_list)):
            black_ip = sub_domain2ip_history(sub_domain_list[i])
            black_ip_list = black_ip_list + black_ip
            time.sleep(random.random()*2)

        black_ip_list = list(set(black_ip_list))

        with open('black_ip.txt', 'a') as f:
            for item in black_ip_list:
                f.write(item + '\n')

    # 再用集合过一遍
    with open('./black_ip.txt', 'r') as f:
        data = f.read()

    data = data.split('\n')
    data = list(set(data))

    with open('./black_ip.txt', 'w') as f:
        for item in data:
            f.write(item + '\n')
