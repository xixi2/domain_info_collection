"""
读取niclog_url文件，取出其中的域名，然后形成一个集合。
将每个这样的域名集合和恶意域名集合（恶意域名数据集）做交运算
"""
import os
import sys
import json
import time
from pymongo import MongoClient
from common.mongodb_op import mongo_url, load_bad_or_good_domains
from common.common_niclog_url import NICLOG_URL_FILE_DIR, FILE_NAME_SUFFIX, FILE_NAME_PREFIX
from common.common_niclog_url import HOST_NAME
from common.date_op import generate_day_seq
from common.domains_op import keep_2nd_dom_name, is_domain_ip, write2file
from common.other_common import remove_file
from get_visited_bad_domains_info.get_mal_domains_from_niclog import load_bad_niclog_domains

client = MongoClient(mongo_url)
START_DAY = "2019.04.10"
FILE_SEQ = 10
BAD_URL_DOMAINS_FILE = "bad_niclog_url.txt"
GOOD_URL_DOMAINS_FILE = "good_niclog_url.txt"


def tackle_line(line):
    line = line.strip("\n")
    line = json.loads(line)
    domain = line.get(HOST_NAME, "")
    domain_2nd = ""
    if domain and not is_domain_ip(domain):
        domain_2nd = keep_2nd_dom_name(domain)
    return domain_2nd


def read_niclog_url_file(file):
    unknown_domain_set = set()
    f_out = open(file)
    I = iter(f_out)
    file_total_line = 0
    while True:
        try:
            file_total_line += 1
            line = next(I)
            domain_2nd = tackle_line(line)
            if domain_2nd:
                # print("domain: %s" % domain_2nd)
                unknown_domain_set.add(domain_2nd)
        except StopIteration as e:
            print("StopIteration %s" % (e))
            break
        except Exception as e:
            # print("error read file %s for %s" % (file, e))
            pass
    print("totally captured %s domains" % (len(unknown_domain_set)))
    print("file %s totally has %s lines" % (file, file_total_line))
    return unknown_domain_set


def get_niclog_url_file_list(dir=NICLOG_URL_FILE_DIR):
    file_list = []
    dt_str_seq = generate_day_seq(START_DAY, 2)
    for dt_str in dt_str_seq:
        for i in range(FILE_SEQ):
            file = dir + FILE_NAME_PREFIX + dt_str + "_" + str(i) + FILE_NAME_SUFFIX
            if not os.path.exists(file):
                # print("file: %s not exist" % file)
                continue
            file_list.append(file)
    return file_list


def read_niclog_url_files(file_list, mal_domain_set):
    for file in file_list:
        start_time = time.time()
        unknown_domain_set = read_niclog_url_file(file)
        end_time = time.time()
        cost_time = end_time - start_time
        print("==================================================================")
        print("%s domains, size: %s Kbytes" % (len(unknown_domain_set), sys.getsizeof(unknown_domain_set) / 1024))
        print("cost_time: %s 秒" % (cost_time))
        insect_domains = unknown_domain_set & mal_domain_set
        print("%s bad domains found in file %s" % (len(insect_domains), file))
        write2file(BAD_URL_DOMAINS_FILE, insect_domains)


def remove_duplicate_from_file(file):
    domain_set = set()
    with open(file) as f_out:
        lines = f_out.readlines()
        for line in lines:
            domain = line.strip("\n")
            domain_set.add(domain)
    remove_file(file)
    write2file(file, domain_set)
    print("%s unique bad domains" % (len(domain_set)))


if __name__ == "__main__":
    domain_bad = 1
    # 加载恶意域名数据集中的恶意域名或者 正常域名
    # domain_list = load_bad_or_good_domains(client, domain_bad)
    # 加载niclog中找到的恶意域名
    domain_list = load_bad_niclog_domains()

    mal_domain_set = set(domain_list)
    print(" %s domains, size: %s Kbytes" % (len(mal_domain_set), sys.getsizeof(mal_domain_set) / 1024))
    file_list = get_niclog_url_file_list()
    read_niclog_url_files(file_list, mal_domain_set)
    remove_duplicate_from_file(BAD_URL_DOMAINS_FILE)
