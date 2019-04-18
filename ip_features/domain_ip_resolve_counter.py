# coding:utf-8
"""
所有与IP相关的信息都在domain_ip_resolution数据块中，接下来分析这个数据库中数据得到与ip这个特征相关的新
与IP有关的特征：
    恶意域名可以映射到几个IP
    恶意域名与多少个其他域名共享IP

    恶意IP（恶意域名可以映射到的IP）
    恶意IP被多少个域名共享
    恶意IP与多少个其他IP能够映射到同一个域名
"""
import numpy as np
from pymongo import MongoClient
from common.mongodb_op import mongo_url
from common.mongodb_op import DOMAIN_IP_RESOLUTION_MONGO_DB, GOOD_DOMAINS_MONGO_DB, \
    MAL_DOMS_MONGO_DB, GOOD_DOMAIN_IP_MONGO_INDEX, BAD_DOMAIN_IP_MONGO_INDEX, MAL_DOMS_MONGO_INDEX, \
    GOOD_IPS_MONGO_INDEX, BAD_IPS_MONGO_INDEX
from common.mongo_common_fields import IP_FIELD, IPS_FIELD, DOMAIN_2ND_FIELD
from common.draw_picture import draw_bar, draw_two_bar

client = MongoClient(mongo_url)
db_good_doamin = client[GOOD_DOMAINS_MONGO_DB]
db_bad_domain = client[MAL_DOMS_MONGO_DB]
db_ips = client[DOMAIN_IP_RESOLUTION_MONGO_DB]

NUMBER_OF_TOTAL_BAD_DOMAINS = 8040
NUMBER_OF_TOTAL_GOOD_DOMAINS = 2012


def get_number_of_unique_ips2single_domain(db_ips, domain_ip_mongo_index):
    recs = db_ips[domain_ip_mongo_index].find()
    unique_ips_number_set = set()
    number_of_domains = {}
    for rec in recs:
        ips = rec[IPS_FIELD]
        number_of_ips = len(ips)
        unique_ips_number_set.add(number_of_ips)  # 域名对应IP个数的种类：即域名能够对应多少种不同个数的IP
        number = number_of_domains.get(number_of_ips, 0)  # 对应每种数目的IP的域名有多少个，如某些域名对应1个IP，那么这样的域名有多少个
        number_of_domains[number_of_ips] = number + 1

    print("len of unique_ips_number_set: %s" % (len(unique_ips_number_set)))
    print("len of number_of_domains: %s" % (len(number_of_domains)))
    print("max of unique_ips_number_set: %s, min of unique_ips_number_set: %s" % (
        max(unique_ips_number_set), min(unique_ips_number_set)))
    return unique_ips_number_set, number_of_domains


def get_number_of_unique_domains_sharing_ip(db_ips, ip_mongo_index):
    recs = db_ips[ip_mongo_index].find()
    unique_domains_number_set = set()  # 每个IP对应着不同数目的域名，共有多少种不同数目
    number_of_ips = {}  # 对应着不同数目域名的IP各种多少种
    for rec in recs:
        domains = rec[DOMAIN_2ND_FIELD]
        number_of_domains = len(domains)
        unique_domains_number_set.add(number_of_domains)
        number = number_of_ips.get(number_of_domains, 0)
        number_of_ips[number_of_domains] = number + 1
    print("len of unique_domains_number_set: %s" % (len(unique_domains_number_set)))
    print("len of number_of_domains: %s" % (len(number_of_ips)))
    print("max of number_of_unique_domains: %s, min of unique_number_of_ips: %s" % (
        max(unique_domains_number_set), min(unique_domains_number_set)))
    return unique_domains_number_set, number_of_ips


def draw_out_unique_number(title, func, mongo_index, x_min, x_max):
    print(title)
    unique_number_set, number_dict = func(db_ips, mongo_index)
    draw_bar(list(number_dict.keys()), list(number_dict.values()), x_min, x_max, title)


if __name__ == '__main__':
    bad_title_ips = u"每个恶意域名映射到的IP的数量X"
    good_title_ips = u"每个正常域名映射到的IP的数量X"
    bad_title_domains = u"每个恶意IP映射到的域名的数量X"
    good_title_domains = u"每个正常IP映射到的域名的数量X"
    # x_min, x_max = 0, 50
    # draw_out_unique_number(bad_title_ips, get_number_of_unique_ips2single_domain, BAD_DOMAIN_IP_MONGO_INDEX, x_min,
    #                        x_max)
    # draw_out_unique_number(good_title_ips, get_number_of_unique_ips2single_domain, GOOD_DOMAIN_IP_MONGO_INDEX, x_min,
    #                        x_max)

    print("==================================================================")
    label1 = "恶意域名"
    label2 = "正常域名"
    title = "正常域名和恶意域名映射到的IP数量x比较"
    unique_number_set_bad, number_dict_bad = get_number_of_unique_ips2single_domain(db_ips, BAD_DOMAIN_IP_MONGO_INDEX)
    unique_number_set_good, number_dict_good = get_number_of_unique_ips2single_domain(db_ips,
                                                                                      GOOD_DOMAIN_IP_MONGO_INDEX)

    # x1表示的是域名映射到的IP的个数
    x1, y1 = list(number_dict_bad.keys()), list(number_dict_bad.values())
    x2, y2 = list(number_dict_good.keys()), list(number_dict_good.values())
    x1_1, y1_1 = np.array(x1), np.array(y1)
    x2_1, y2_1 = np.array(x2), np.array(y2)
    x1_1 = x1_1
    y1_1 = y1_1/ NUMBER_OF_TOTAL_BAD_DOMAINS
    x2_1 = x2_1
    y2_1 = y2_1/ NUMBER_OF_TOTAL_GOOD_DOMAINS
    # draw_two_bar(x1, y1, x2, y2, label1, label2, title)
    x_min, x_max = 0, 40
    width = 0.2
    draw_two_bar(x1_1, y1_1, x2_1, y2_1, x_min, x_max, width, label1, label2, title)

    print("==================================================================")
    x_min, x_max = 0, 10
    # draw_out_unique_number(bad_title_domains, get_number_of_unique_domains_sharing_ip, BAD_IPS_MONGO_INDEX, x_min, x_max)
    # draw_out_unique_number(good_title_domains, get_number_of_unique_domains_sharing_ip, GOOD_IPS_MONGO_INDEX, x_min, x_max)
