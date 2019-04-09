import os
import re
import pandas as pd
from pymongo import MongoClient

from common.domains_op import VER_DOM_DIR
from common.domains_op import read_domain_file
from common.mongodb_op import mongo_url, MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, MAL_DOMAINS_MONGO_INDEX
from common.mongo_common_fields import DOMAIN_2ND_FIELD, SOURCE_SIET, MAL_TYPE
from common.domains_op import keep_2nd_dom_name, PRE_DIR
from common.common_domain_source import allowed_sources
from common.index_op_mal_dom import set_mal_domain_index_params1, get_domains_with_type

client = MongoClient(mongo_url)
domain_source_dict = {
    "abuse": "urlhaus.abuse.ch",
    "cybercrime": "cybercrime-tracker.net",
    "feodo": "www.abuse.ch",
    "zeus": "zeustracker.abuse.ch",
    "malwaredomains": "malwaredomains.com",
    "malwaredomainlist": "malwaredomainlist.com",
    "phishtank": "www.phishtank.com",
    "spyeye": "spyeyetracker.abuse.cn",
    "palevo": "unknow",
    "ransomware": "ransomwaretracker.abuse.ch",
}

# 已知域名的来源即可确认域名的恶意类型：其实还是比较主观
domain_type_dict = {
    "www.phishtank.com": "phishing",
    "ransomwaretracker.abuse.ch": "ransomware",
}


def read_ver_domains2database(dir):
    """
    将已经确认过的恶意域名存入mongodb数据库
    :param dir:
    :return:
    """
    files = os.listdir(dir)
    for file in files:
        ver_file = VER_DOM_DIR + file
        print(ver_file)
        domains = read_domain_file(ver_file)
        help_field = file.split("_")[0]
        source = domain_source_dict.get(help_field, None)
        mal_type = domain_type_dict.get(source, None)
        print("help_field: %s" % (help_field))
        print("%s domains save2mongodb" % (len(domains)))
        # save2mongodb(domains, source, type, MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX)
        source_list = [] if not source else [source, ]
        type_list = [] if not mal_type else [mal_type, ]
        save2mongodb(domains, source_list, type_list, MAL_DOMS_MONGO_DB, MAL_DOMAINS_MONGO_INDEX)


def set_rec_body(source_list, type_list):
    if not type_list and not source_list:
        rec_body = {}
    else:
        rec_body = {"$addToSet": {}}
        if type_list:
            rec_body["$addToSet"][MAL_TYPE] = {"$each": type_list}
        if source_list:
            rec_body["$addToSet"][SOURCE_SIET] = {"$each": source_list}
    return rec_body


def save2mongodb(domains, source_list, type_list, db_name, mongo_index_name):
    """
    :param domains: 要存入mangodb的域名集合
    :param source: 每个域名的来源
    :param type: 每个域名的恶意类型，如钓鱼网站，垃圾邮件
    :param db_name: mongodb数据库名
    :param mongo_index_name: mongodb数据库索引名
    :param insert_new: 当未在数据库中找到响应的域名时是否插入新的记录
    :return:
    """
    db = client[db_name]
    for domain in domains:
        query_body = {DOMAIN_2ND_FIELD: domain}
        rec_body = set_rec_body(source_list, type_list)
        db[mongo_index_name].update(query_body, rec_body, True)


def save_one_domain2mongodb(domain, source_list, type_list, db_name, mongo_index_name, insert_new=False):
    """
    :param domains: 要存入mangodb的域名集合
    :param source: 每个域名的来源
    :param type: 每个域名的恶意类型，如钓鱼网站，垃圾邮件
    :param db_name: mongodb数据库名
    :param mongo_index_name: mongodb数据库索引名
    :param insert_new: 当未在数据库中找到响应的域名时是否插入新的记录
    :return:
    """
    db = client[db_name]
    query_body = {DOMAIN_2ND_FIELD: domain}
    rec_body = set_rec_body(source_list, type_list)
    db[mongo_index_name].update(query_body, rec_body, insert_new)
    exist = db[mongo_index_name].find(query_body).count()
    if exist:
        print("domain: %s, type: %s, exist: %s" % (domain, type_list, exist))


def read_csv_update_type(csv_file):
    """
    从csv文件中读取出一些域名的恶意类型，并在恶意域名数据库中查询响应域名并修改恶意类型
    :return:
    """
    df = pd.read_csv(csv_file)
    for i in range(len(df)):
        print("domain: %s, type: %s" % (df.loc[i]["domain"], df.loc[i]["type"]))
        type = df.loc[i]["type"]
        save_one_domain2mongodb(df.loc[i][DOMAIN_2ND_FIELD], [], [type, ], MAL_DOMS_MONGO_DB, MAL_DOMAINS_MONGO_INDEX)


def read_domain_txt(txt_file, dst_file):
    """
    将源文件txt_file中的域名与恶意类型提取出来
    :param txt_file:
    :param dst_file:
    :return:
    """
    domain_tuple_list = []
    not_allowed_phreas = ("#",)
    with open(txt_file) as f_out:
        for line in f_out.readlines():
            line = line.strip("\n")
            line_list = [item for item in line.split("\t") if item and item not in not_allowed_phreas]

            type = line_list[1]
            domain_2nd = keep_2nd_dom_name(line_list[0])
            if len(line_list) >= 3:
                source = line_list[2]
                if source in allowed_sources:
                    domain_tuple_list.append((domain_2nd, type, source))
                else:
                    domain_tuple_list.append((domain_2nd, type, ""))
                # print("domain: %s, type: %s, source: %s" % (domain_2nd, type, source))
            if len(line_list) % 4 == 0 and len(line_list) > 4:
                for i in range(1, (len(line_list) // 4) - 1):
                    domain_2nd = keep_2nd_dom_name(line_list[4 * i])
                    if re.search("\d+.", domain_2nd):
                        continue
                    type = line_list[4 * i + 1]
                    source = line_list[4 * i + 2]
                    if source in allowed_sources:
                        domain_tuple_list.append((domain_2nd, type, source))
                    else:
                        domain_tuple_list.append((domain_2nd, type, ""))
            # print("line_list: %s" % (line_list,))
    with open(dst_file, "a+") as f_in:
        for domain_2nd, type, source in domain_tuple_list:
            f_in.write(domain_2nd + "," + type + "\n")


def read_txt_update_type(txt_file):
    with open(txt_file) as f_out:
        for line in f_out.readlines():
            domain_2nd, type = line.strip("\n").split(",")
            # print("domain: %s, type: %s" % (domain_2nd, type))
            save_one_domain2mongodb(domain_2nd, [], [type, ], MAL_DOMS_MONGO_DB, MAL_DOMAINS_MONGO_INDEX)


def update_es_domains_source_and_type():
    """ 修改来自es_non_dga.txt文件中的域名的source字段和type字段"""
    query_body = {"query": {"bool": {"must_not": [{"query_string": {"default_field": "info.Desc", "query": "DGA"}}]}}}
    domain_dict = set_mal_domain_index_params1(get_domains_with_type, query_body)
    for domain, info_tuple in domain_dict.items():
        source, mal_type = info_tuple[0], info_tuple[1]
        print("domain:%s, source: %s, mal_type: %s" % (domain, info_tuple[0], info_tuple[1]))
        source_list = [] if not source else [source, ]
        type_list = [] if not mal_type else [mal_type, ]
        save_one_domain2mongodb(domain, source_list, type_list, MAL_DOMS_MONGO_DB, MAL_DOMAINS_MONGO_INDEX)


if __name__ == "__main__":
    # 从文件读取出恶意域名对应的恶意类型，存入写的文件，等待插入数据库
    csv_file = "../data_set/bad_domains/abuse_simple_2019.csv"
    # txt_file = PRE_DIR + "domains.txt"
    dst_file = PRE_DIR + "domains_after.txt"
    # read_domain_txt(txt_file, dst_file)

    # 将恶意域名存储数据库并修改其恶意类型
    domains = read_ver_domains2database(VER_DOM_DIR)
    update_es_domains_source_and_type()
    read_csv_update_type(csv_file)
    read_txt_update_type(dst_file)
