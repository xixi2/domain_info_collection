"""
本文件夹的作用：从ES中寻找访问过恶意域名或正常域名的记录。
从ES中的niclog日志中找到正常域名数据集和恶意域名数据集中域名的访问记录。
插入到mongodb中的数据库nic_log_visiting中，
    其中bad_domain_subdomain和good_domain_subdomain分别存储正常和恶意域名及访问过的三级子域名
"""
import time
from elasticsearch import helpers, Elasticsearch
from pymongo import MongoClient

from common.date_op import generate_day_seq
from common.mongodb_op import MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, NIC_LOG_MONGO_DB, \
    NIC_LOG_BAD_DOMAIN_SUBDOMAINS_MONGO_INDEX, GOOD_DOMAINS_MONGO_DB, GOOD_DOMAINS_MONGO_INDEX, \
    NIC_LOG_GOOD_DOMAIN_SUBDOMAINS_MONGO_INDEX, NIC_LOG_GOOD_FULL_NAME_VISITING_MONGO_INDEX, \
    DOMAIN_SUBDOMAIN_MONGO_INDEX, NIC_LOG_BAD_FULL_NAME_VISITING_MONGO_INDEX
from common.mongodb_op import mongo_url
from common.mongodb_op import query_mongodb_by_body, save_domain_subdomains2mongodb
from common.date_op import timestamp_str2ymdh
from common.domains_op import keep_3th_dom_name
from common.mongo_common_fields import FULL_DOMAIN, DOMAIN_2ND_FIELD

client = MongoClient(mongo_url)
db_nic_log = client[NIC_LOG_MONGO_DB]

PERIOD_START = '2019.04.10'  # 查询开始日期
DAY_RANGE = 14
HOST = "10.1.1.201:9200"
VIS_DOMAIN_INDEX_NAME_PREFIX = "niclog-4th-"
VIS_DOM_DOC_TYPE = 'logs4th'
VISITORS = "visitors"
DT_STRS = "dt_strs"


def save_full_domains_visiting_records2mongodb(full_domain, db, mongo_index, date_str, visitor):
    basic_body = {}
    if date_str or visitor:
        basic_body["$addToSet"] = {}
    if date_str:
        basic_body["$addToSet"]["dates"] = {"$each": date_str}
    if visitor:
        basic_body["$addToSet"][VISITORS] = {"$each": visitor}
    db[mongo_index].update({FULL_DOMAIN: full_domain}, basic_body, True)


def match_domains_in_es(domain_list, query_start_date, day_range, domain_bad, index_prefix):
    assert domain_bad == 0 or domain_bad == 1
    dt_str_seq = generate_day_seq(query_start_date, day_range, forward=-1)
    doc_type = VIS_DOM_DOC_TYPE
    es = Elasticsearch(hosts=HOST, timeout=10, sniff_on_start=True, sniff_on_connection_fail=True,
                       sniffer_timeout=60, sniff_timeout=10)
    for index_name_suffix in dt_str_seq:
        index_name = index_prefix + index_name_suffix
        print('index_name: {0}'.format(index_name))
        print('len of domains: {0}'.format(len(domain_list)))
        matched_all = 0
        for index, domain in enumerate(domain_list):
            # print("handlering index: %s domain %s" % (index, domain))
            matched = search_domain_in_es(es, index_name, doc_type, domain)
            matched_all += 1 if matched else 0
        print("daily matced: %s" % matched_all)


def search_domain_in_es(es, index_name, doc_type, domain_2nd):
    matched = False  # 该域名是否在niclog中匹配
    pattern = "([A-Za-z0-9-]?[A-Za-z0-9]+\.)?" + domain_2nd
    query_body = {
        "query": {"bool": {"must": [{"regexp": {"content": pattern}}, {"term": {"operation": "dnsquery3"}}]}}}
    if es.indices.exists(index_name):
        gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body, scroll='30m')
        full_domains_visit_dict = {}
        sub_domains = set()  # 三级域名
        for item in gen:
            item = item['_source']
            full_domain = item['content']
            visitor = item["source-mac"]  # 访问该域名的用户，使用mac地址标识
            visit_date = item['time-stamp']
            dt_str = timestamp_str2ymdh(visit_date)
            if full_domain not in full_domains_visit_dict:
                full_domains_visit_dict[full_domain] = {VISITORS: [], DT_STRS: []}
            full_domains_visit_dict[full_domain][VISITORS].append(visitor)
            full_domains_visit_dict[full_domain][DT_STRS].append(dt_str)
            pos = full_domain.lower().find(domain_2nd.lower())

            # 在全域名中包含了二级域名或者全域名就是二级域名本身,将全域名对应的三级域名加入到二级域名的子域名列表中
            if pos == 0 or pos > 0 and full_domain[pos - 1] == '.':
                sub_domains.add(keep_3th_dom_name(full_domain))
                # print("domain_2nd: %s, matched full_domain: %s" % (domain_2nd, keep_3th_dom_name(full_domain)))

        # 把匹配到的域名信息存入到MongoDB数据库中
        sub_domains = list(sub_domains)
        if domain_bad:
            if len(sub_domains):
                save_domain_subdomains2mongodb(
                    domain_2nd.lower(), sub_domains, db_nic_log, NIC_LOG_BAD_DOMAIN_SUBDOMAINS_MONGO_INDEX)
            for full_domain in full_domains_visit_dict:
                visitors = full_domains_visit_dict[full_domain]["visitors"]
                dt_strs = full_domains_visit_dict[full_domain]["dt_strs"]
                save_full_domains_visiting_records2mongodb(
                    full_domain, db_nic_log, NIC_LOG_BAD_FULL_NAME_VISITING_MONGO_INDEX, dt_strs,
                    visitors)
        else:
            # 当full_domains或者visitors数量过大时，无法一次插入到mongodb中，需要分成多次插入
            batch_num = 400
            if len(sub_domains) > batch_num:
                total = 0
                while total < len(sub_domains):
                    size = batch_num if len(sub_domains) - total > batch_num else len(sub_domains) - total
                    save_domain_subdomains2mongodb(domain_2nd.lower(), sub_domains[total: total + size],
                                                   db_nic_log,
                                                   NIC_LOG_GOOD_DOMAIN_SUBDOMAINS_MONGO_INDEX)
                    total += size
            else:
                save_domain_subdomains2mongodb(domain_2nd.lower(), sub_domains, db_nic_log,
                                               NIC_LOG_GOOD_DOMAIN_SUBDOMAINS_MONGO_INDEX)
            for full_domain in full_domains_visit_dict:
                visitors = full_domains_visit_dict[full_domain]["visitors"]
                dt_strs = full_domains_visit_dict[full_domain]["dt_strs"]

                # 当访问者数量过多时，批量插入，不是一次性插入，一次性插入可能会超过MongoDB单次允许插入的数量而出错
                if len(visitors) > batch_num:
                    print("len of visitors: %s" % (len(visitors)))
                    total = 0
                    while total < len(visitors):
                        size = batch_num if len(visitors) - total > batch_num else len(visitors) - total
                        save_full_domains_visiting_records2mongodb(
                            full_domain, db_nic_log, NIC_LOG_GOOD_FULL_NAME_VISITING_MONGO_INDEX,
                            dt_strs[total: total + size], visitors[total: total + size])
                        total += size
                    #     print("total: %s" % (total))
                    # print("break while total: %s" % (total))
                else:
                    save_full_domains_visiting_records2mongodb(
                        full_domain, db_nic_log, NIC_LOG_GOOD_FULL_NAME_VISITING_MONGO_INDEX, dt_strs,
                        visitors)

        if len(sub_domains):
            matched = True
            print("==============domain: %s matched, len(sub_domains): %s================" % (
                domain_2nd, len(sub_domains)))
    return matched


def get_domains_from_dataset(domain_bad):
    fields = [DOMAIN_2ND_FIELD, ]
    if domain_bad:
        # 取出mongodb中所有的恶意域名
        recs = query_mongodb_by_body(client, MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, fields)
    else:  # 从mongodb中取出所有的正常域名
        recs = query_mongodb_by_body(client, GOOD_DOMAINS_MONGO_DB, GOOD_DOMAINS_MONGO_INDEX, fields)
    return recs


def get_domains_from_dataset_v1(domain_bad, query_body=None):
    mongo_db_dict = {
        1: MAL_DOMS_MONGO_DB,
        0: GOOD_DOMAINS_MONGO_DB
    }
    mongo_index_dict = {
        0: GOOD_DOMAINS_MONGO_INDEX,
        1: MAL_DOMS_MONGO_INDEX
    }
    mongo_db = mongo_db_dict.get(domain_bad)
    db = client[mongo_db]
    mongo_index = mongo_index_dict.get(domain_bad)
    recs = []
    if not query_body:
        rec = db[mongo_index].find()
        # print("ans: %s" % (rec.count(),))
    else:
        rec = db[mongo_index].find(query_body)
        # print("ans: %s" % (rec.count(),))
    for item in rec:
        del item["_id"]
        recs.append(item)
    return recs


if __name__ == "__main__":
    domain_bad = int(input("please a number: 0 for query good domains, 1 for query bad domains"))
    domain_list = []
    fields = [DOMAIN_2ND_FIELD, ]
    if domain_bad:
        # 取出mongodb中所有的恶意域名
        domain_list = query_mongodb_by_body(client, MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, fields)
    else:  # 从mongodb中取出所有的正常域名
        domain_list = query_mongodb_by_body(client, GOOD_DOMAINS_MONGO_DB, GOOD_DOMAINS_MONGO_INDEX, fields)
        # total_num = len(domain_list)
        # start_num = 1400
        # batch_num = 200
        # domain_list = domain_list[start_num: min(start_num + batch_num, total_num)]  # 速度太慢，只能出此下策

    print("len of domains: %s" % len(domain_list))
    query_start_date = PERIOD_START
    day_range = DAY_RANGE
    query_start_date = input("please enter a date(format: 2019.03.19 for default it is %s" % (query_start_date,))
    day_range = int(input("please enter how many days would you like to query, for default this is %s" % (day_range)))

    match_domains_in_es(domain_list, query_start_date, day_range, domain_bad, VIS_DOMAIN_INDEX_NAME_PREFIX)
