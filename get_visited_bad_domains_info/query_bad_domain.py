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
from common.other_common import CHOICE_OF_GOOD, CHOICE_OF_BAD
from common.date_op import timestamp_str2ymdh

client = MongoClient(mongo_url)
db_nic_log = client[NIC_LOG_MONGO_DB]

HOST = "10.1.1.201:9200"
VIS_DOMAIN_INDEX_NAME_PREFIX = "niclog-4th-"
VIS_DOM_DOC_TYPE = 'logs4th'


def save_full_domains_visiting_records2mongodb(full_domain, db, mongo_index, date_str, visitor):
    basic_body = {}
    if date_str or visitor:
        basic_body["$addToSet"] = {}
    if date_str:
        basic_body["$addToSet"]["dates"] = {"$each": date_str}
    if visitor:
        basic_body["$addToSet"]["visitors"] = {"$each": visitor}
    db[mongo_index].update({"full_domain": full_domain}, basic_body, True)


def search(domains, query_start_date, day_range, choice):
    """
    :param domains:
    :param query_start_date: 从这一天往前（日期减少）查询
    :param choice: 在niclog中查询正常域名还是恶意域名
    :return:
    """
    dt_str_seq = generate_day_seq(query_start_date, day_range, forward=-1)
    doc_type = VIS_DOM_DOC_TYPE

    # 连接不能写在循环中
    es = Elasticsearch(hosts=HOST, timeout=10, sniff_on_start=True, sniff_on_connection_fail=True,
                       sniffer_timeout=60, sniff_timeout=10)
    for index_name_suffix in dt_str_seq:
        index_name = VIS_DOMAIN_INDEX_NAME_PREFIX + index_name_suffix
        print('index_name: {0}'.format(index_name))
        print('len of domains: {0}'.format(len(domains)))
        # query_body = {"query": {"regexp": {"content": ""}}}
        for index in range(len(domains)):
            pattern = "([A-Za-z0-9-]?[A-Za-z0-9]+\.)?" + domains[index]
            query_body = {
                "query": {"bool": {"must": [{"regexp": {"content": pattern}}, {"term": {"operation": "dnsquery3"}}]}}}
            if es.indices.exists(index_name):
                gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body)
                full_domains_visit_dict = {}
                full_domains = []
                for item in gen:
                    item = item['_source']
                    full_domain = item['content']
                    visitor = item["source-mac"]  # 访问该域名的用户，使用mac地址标识
                    visit_date = item['time-stamp']
                    dt_str = timestamp_str2ymdh(visit_date)
                    if full_domain not in full_domains_visit_dict:
                        full_domains_visit_dict[full_domain] = {"visitors": [], "dt_strs": []}
                    full_domains_visit_dict[full_domain]["visitors"].append(visitor)
                    full_domains_visit_dict[full_domain]["dt_strs"].append(dt_str)
                    full_domains.append(full_domain)

                if choice == CHOICE_OF_BAD:
                    save_domain_subdomains2mongodb(
                        domains[index], full_domains, db_nic_log, NIC_LOG_BAD_DOMAIN_SUBDOMAINS_MONGO_INDEX)
                    for full_domain in full_domains_visit_dict:
                        visitors = full_domains_visit_dict[full_domain]["visitors"]
                        dt_strs = full_domains_visit_dict[full_domain]["dt_strs"]
                        save_full_domains_visiting_records2mongodb(
                            full_domain, db_nic_log, NIC_LOG_BAD_FULL_NAME_VISITING_MONGO_INDEX, dt_strs,
                            visitors)
                elif choice == CHOICE_OF_GOOD:
                    save_domain_subdomains2mongodb(domains[index], full_domains, db_nic_log,
                                                   NIC_LOG_GOOD_DOMAIN_SUBDOMAINS_MONGO_INDEX)
                    for full_domain in full_domains_visit_dict:
                        visitors = full_domains_visit_dict[full_domain]["visitors"]
                        dt_strs = full_domains_visit_dict[full_domain]["dt_strs"]
                        save_full_domains_visiting_records2mongodb(
                            full_domain, db_nic_log, NIC_LOG_GOOD_FULL_NAME_VISITING_MONGO_INDEX, dt_strs,
                            visitors)
            print("index: %s matched， domain: %s" % (index, domains[index],))

        time.sleep(20)


if __name__ == "__main__":
    choice = int(input("please a number: 0 for query good domains, 1 for query bad domains"))
    domain_list = []
    fields = ["domain"]
    if choice == CHOICE_OF_GOOD:
        # 从mongodb中取出所有的正常域名
        domain_list = query_mongodb_by_body(client, GOOD_DOMAINS_MONGO_DB, GOOD_DOMAINS_MONGO_INDEX, fields)
        # domain_list = domain_list[280:290]  # 速度太慢，只能出此下策
        domain_list = domain_list[350:500]  # 速度太慢，只能出此下策
    elif choice == CHOICE_OF_BAD:
        # 取出mongodb中所有的恶意域名
        domain_list = query_mongodb_by_body(client, MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, fields)
    print("len of domains: %s" % len(domain_list))

    query_start_date = input("please enter a date(format: 2019.03.19")
    day_range = int(input("please enter how many days would you like to query, for default this is 7"))
    search(domain_list, query_start_date, day_range, choice)
