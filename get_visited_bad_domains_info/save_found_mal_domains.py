"""
将之间收集的8140个恶意域名数据集中能够找到的141个恶意域名写入文件，等待插入到后来从niclog日志找到的恶意域名数据集中
"""
from pymongo import MongoClient
from time_features.extract_time_seq2csv import get_visited_domains
from common.mongodb_op import mongo_url
from common.mongodb_op import MAL_DOMS_MONGO_DB, MAL_DOMAINS_MONGO_INDEX
from common.mongo_common import DOMAIN_2ND_FIELD, MAL_TYPE, SOURCE_SIET
from common.domains_op import write2file
from get_visited_bad_domains_info.get_mal_domains_from_niclog import OLD_141_BAD_DOMAINS_FILE

client = MongoClient(mongo_url)


def show_visited_bad_domains(domains):
    """
    显示从niclog中能够匹配的141恶意域名及其来源、恶意类型等信息
    :return:
    """
    db = client[MAL_DOMS_MONGO_DB]
    mongo_index = MAL_DOMAINS_MONGO_INDEX
    for domain_2nd in domains:
        query_body = {DOMAIN_2ND_FIELD: domain_2nd}
        recs = db[mongo_index].find(query_body)
        mal_type = recs[0].get(MAL_TYPE, "unknown")
        source = recs[0].get(SOURCE_SIET, "unknown")
        print("domain %s captured, source: %s, type: %s" % (domain_2nd, source, mal_type))


if __name__ == '__main__':
    domain_bad = 1
    domains = get_visited_domains(domain_bad)
    show_visited_bad_domains(domains)
    write2file(OLD_141_BAD_DOMAINS_FILE, domains)
