import time
import pandas as pd
from pymongo import MongoClient
from common.mongodb_op import mongo_url
from ip_features.prepare_data import get_domains_dataset
from common.mongodb_op import DOMAIN_IP_RESOLUTION_MONGO_DB, GOOD_DOMAINS_MONGO_DB, \
    MAL_DOMS_MONGO_DB, GOOD_DOMAIN_IP_MONGO_INDEX, BAD_DOMAIN_IP_MONGO_INDEX, MAL_DOMS_MONGO_INDEX, \
    GOOD_IPS_MONGO_INDEX, BAD_IPS_MONGO_INDEX, GOOD_DOMAINS_MONGO_INDEX
from common.mongo_common_fields import IP_FIELD, IPS_FIELD, DOMAIN_2ND_FIELD

client = MongoClient(mongo_url)
db_good_doamin = client[GOOD_DOMAINS_MONGO_DB]
db_bad_domain = client[MAL_DOMS_MONGO_DB]
db_ips = client[DOMAIN_IP_RESOLUTION_MONGO_DB]

NUMBER_OF_UNIQUE_IPS = "number_of_unique_ips"
NUMBER_OF_DOMAINS = "number_of_domains"
GOOD_IP_FEATURE_FILE = "good_ip_feature.csv"
BAD_IP_FEATURE_FILE = "bad_ip_feature.csv"


def get_number_of_ips_and_domains_sharing_ip_with(domain, domain_mongo_index, ip_mongo_index):
    """
    :param domain: 要查询的域名
    :param domain_mongo_index:
    :param ip_mongo_index:
    :return:
        number_of_domains： 此域名映射到的ip地址个数
        number_of_unique_ips：与此域名共享ip的域名个数
    """
    number_of_domains, number_of_unique_ips = 0, 0
    query_body = {DOMAIN_2ND_FIELD: domain}
    rec = db_ips[domain_mongo_index].find(query_body)
    if rec.count() > 0:
        domain_info = rec[0]
        ips = domain_info[IPS_FIELD]
        number_of_unique_ips = len(ips)
        if not number_of_unique_ips:
            print("notexist domain: %s" % domain)
        for ip in ips:
            query_body = {IP_FIELD: ip}
            ans = db_ips[ip_mongo_index].find(query_body)
            if ans.count() > 0:
                domains = ans[0][DOMAIN_2ND_FIELD]
                number_of_domains += len(domains) - 1  # -1是为了减掉自己
    return number_of_unique_ips, number_of_domains


def ip_feature2csv(domain_list, domain_mongo_index, ip_mongo_index, ip_feature_file):
    ip_feature_dict_list = []
    iter = 0
    for domain in domain_list:
        number_of_unique_ips, number_of_domains = get_number_of_ips_and_domains_sharing_ip_with(
            domain, domain_mongo_index, ip_mongo_index)
        ip_feature_dict = {
            DOMAIN_2ND_FIELD: domain, NUMBER_OF_UNIQUE_IPS: number_of_unique_ips,
            NUMBER_OF_DOMAINS: number_of_domains
        }
        ip_feature_dict_list.append(ip_feature_dict)

        print("iter: %s, domain: %s" % (iter, domain))
        iter += 1

    df = pd.DataFrame(ip_feature_dict_list, columns=[DOMAIN_2ND_FIELD, NUMBER_OF_UNIQUE_IPS, NUMBER_OF_DOMAINS])
    df.sort_values(by=NUMBER_OF_UNIQUE_IPS)
    df.to_csv(ip_feature_file, index=True)


if __name__ == '__main__':
    start_time = time.time()
    # 提取恶意域名的ip特征
    # bad_domains = get_domains_dataset(db_ips, BAD_DOMAIN_IP_MONGO_INDEX)
    # ip_feature2csv(bad_domains, BAD_DOMAIN_IP_MONGO_INDEX, BAD_IPS_MONGO_INDEX, BAD_IP_FEATURE_FILE)

    # 提取正常域名的ip特征
    good_domains = get_domains_dataset(db_ips, GOOD_DOMAIN_IP_MONGO_INDEX)
    ip_feature2csv(good_domains, GOOD_DOMAIN_IP_MONGO_INDEX, GOOD_IPS_MONGO_INDEX, GOOD_IP_FEATURE_FILE)
    end_time = time.time()
    cost_time = (end_time - start_time) / 60
    print("handler bad domains, cost_time: %s minutes" % (cost_time))
