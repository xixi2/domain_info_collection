"""
本文件是为了能niclog中找到更多的恶意域名:每次从niclog中取出固定数量的域名，提取二级域名后用virustotal验证是否是恶意域名
"""
from elasticsearch import helpers, Elasticsearch
from common.index_201_common import HOST, VIS_DOM_DOC_TYPE, VIS_DOMAIN_INDEX_NAME_PREFIX
from common.domains_op import keep_2nd_dom_name
from common.mongo_common import DOMAIN_2ND_FIELD, DOMAIN_STATUS
from common.mongodb_op import mongo_url, UNCERTAIN_NICLOG_MONGO_DB, UNCERTAIN_NICLOG_MONGO_INDEX
from pymongo import MongoClient
from common.mongo_common import split_domain_rec_v1
from get_visited_bad_domains_info.test_one_domain import scan_url

NUM_OF_DOAMINS = 5000
client = MongoClient(mongo_url)
db_unc = client[UNCERTAIN_NICLOG_MONGO_DB]
mongo_index = UNCERTAIN_NICLOG_MONGO_INDEX
STATUS_ONE = 1
STATUS_ZERO = 0
STATUS_UNKNOW = -1
TARGET_INSERT = 0
TARGET_UPDATE = 1


def format_domain_name(domain_name):
    domain_name = domain_name.lower()
    domain_2nd = keep_2nd_dom_name(domain_name)
    return domain_2nd


def get_all_domains(es, index_name, doc_type, query_body):
    domain_set = set()
    if es.indices.exists(index_name):
        gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body)
        counter = 0
        for item in gen:
            if len(domain_set) >= NUM_OF_DOAMINS:
                break
            counter += 1
            try:
                item = item['_source']
                domain_name = item['content']
                domain_2nd = format_domain_name(domain_name)
                if domain_2nd not in domain_set:
                    print("domain_2nd: %s" % (domain_2nd))
                domain_set.add(domain_2nd)
            except Exception as e:
                print("error: %s" % e)
        print("counter=", counter)
    return list(domain_set)


def set_vis_domain_index_params(index_name_suffix, query_body=None):
    if not query_body:
        query_body = {"query": {"match_all": {}}}
    index_name = VIS_DOMAIN_INDEX_NAME_PREFIX + index_name_suffix
    print('index_name: {0}'.format(index_name))
    doc_type = VIS_DOM_DOC_TYPE
    es = Elasticsearch(hosts=HOST, scroll='5m')
    domain_list = get_all_domains(es, index_name, doc_type, query_body)
    return domain_list


def save_domains2mongo(domain_list, db, status, target):
    """
    :param domain_list:
    :param db:
    :param status:
    :param target: 0:一种是插入，1:一种是修改
    :return:
    当想要插入，但是该域名已经存在于数据库中时，什么也不做
    """
    for domain in domain_list:
        query_body = {DOMAIN_2ND_FIELD: domain}
        basic_body = {DOMAIN_STATUS: status}
        if db[mongo_index].find(query_body).count() > 0:  # 修改状态
            if target == TARGET_INSERT:
                continue
            # print("change doamin: %s status to %s" % (domain, status))
            basic_body = {"$set": basic_body}
            db[mongo_index].update(query_body, basic_body, False)
        else:  # 插入状态
            basic_body[DOMAIN_2ND_FIELD] = domain
            db[mongo_index].insert(basic_body)


def get_every_day_vis_doms(dt_str):
    query_body = {"query": {"match": {"operation": "dnsquery3"}}, "size": NUM_OF_DOAMINS}
    domain_list = set_vis_domain_index_params(dt_str, query_body)
    save_domains2mongo(domain_list, db_unc, STATUS_UNKNOW, TARGET_INSERT)
    print("dom_len: %s" % len(domain_list))


def ver_niclog_domain_bad():
    # query_body = {DOMAIN_STATUS: {"$ne": STATUS_UNKNOW}} #查询所有已知状态的域名
    query_body = {DOMAIN_STATUS: STATUS_UNKNOW}
    recs = db_unc[mongo_index].find(query_body)
    print("recs.count: %s" % (recs.count()))
    domain_bad_batch, domain_good_batch = [], []
    batch_num = 5
    for index, rec in enumerate(recs):
        # if not index:
        # print("rec: ", rec)
        domain_2nd, status = split_domain_rec_v1(rec)
        if status != STATUS_UNKNOW:  # 域名已经验证过了
            continue
        if scan_url(domain_2nd):
            if len(domain_bad_batch) == batch_num:
                print("change domain_bad_batch status to bad")
                save_domains2mongo(domain_bad_batch, db_unc, STATUS_ONE, TARGET_UPDATE)
                domain_bad_batch = []
            domain_bad_batch.append(domain_2nd)
            print("domain %s is bad, len of domain_bad_batch: %s" % (domain_2nd, len(domain_bad_batch)))
        else:
            if len(domain_good_batch) == batch_num:
                save_domains2mongo(domain_good_batch, db_unc, STATUS_ZERO, TARGET_UPDATE)
                domain_good_batch = []
            domain_good_batch.append(domain_2nd)
            # print("domain %s is good" % (domain_2nd))


if __name__ == '__main__':
    # 提取访问的域名
    # dt_str = input("please enter a date, format: %Y.%m.%d")
    # get_every_day_vis_doms(dt_str)
    ver_niclog_domain_bad()
