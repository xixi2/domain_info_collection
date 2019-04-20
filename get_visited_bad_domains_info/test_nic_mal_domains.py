"""
利用query_bad_domain.py从niclog中匹配到正常域名和恶意域名的三级域名后，再利用本文件来验证这些三级域名是否恶意。
验证从niclong中匹配的二级域名的完整域名是否是恶意的。
这些完整域名对应的二级域名是恶意的。
"""
import pandas as pd
import time
import os
from pymongo import MongoClient
from common.mongodb_op import NIC_LOG_MONGO_DB, NIC_LOG_GOOD_DOMAIN_SUBDOMAINS_MONGO_INDEX, \
    NIC_LOG_BAD_DOMAIN_SUBDOMAINS_MONGO_INDEX, NIC_LOG_GOOD_FULL_NAME_VISITING_MONGO_INDEX, \
    NIC_LOG_BAD_FULL_NAME_VISITING_MONGO_INDEX
from common.mongodb_op import mongo_url, save_domain_subdomains2mongodb
from common.mongo_common_fields import DOMAIN_2ND_FIELD, FULL_DOMAIN, SUBDOMAINS_FIELD, VER_SUBDOMAINS_FIELD, \
    SUBDOMAINS_NUMBER, VER_SUBDOMAINS_NUMBER, VER_RATIO
from common.domains_op import write2file, keep_3th_dom_name, keep_2nd_dom_name
from get_visited_bad_domains_info.test_one_domain import scan_url
from common.other_common import remove_file

client = MongoClient(mongo_url)
db_nic_sub_domains = client[NIC_LOG_MONGO_DB]
mongo_index_dict = {
    0: NIC_LOG_GOOD_DOMAIN_SUBDOMAINS_MONGO_INDEX,
    1: NIC_LOG_BAD_DOMAIN_SUBDOMAINS_MONGO_INDEX
}
visiting_mongo_index_dict = {
    0: NIC_LOG_GOOD_FULL_NAME_VISITING_MONGO_INDEX,
    1: NIC_LOG_BAD_FULL_NAME_VISITING_MONGO_INDEX
}
NOT_MAL_DOM_FILE = "not_mal_domains.txt"
BAD_RATIO_FILE = "bad_ratio.csv"
BAD_RATIO_THRESHOLD = 0.8
SUBDOMAIN_NUMBER_THRESHOLD = 0
# SUBDOMAIN_NUMBER_THRESHOLD = 2
BAD_RATIO_ZERO = 0.0


def get_niclog_domains(domain_bad, query_body=None):
    """
    返回niclog中访问过的域名的信息：
    对于恶意域名有：domain, subdomains, ver_mal_sub_domains
    对于正常域名信息有： domain, subdomains
    :param domain_bad: 是否是恶意域名
    :param query_body:
    :return:
    """
    mongo_index = mongo_index_dict.get(domain_bad)
    recs = []
    if not query_body:
        rec = db_nic_sub_domains[mongo_index].find()
        # print("ans: %s" % (rec.count(),))
    else:
        rec = db_nic_sub_domains[mongo_index].find(query_body)
        # print("ans: %s" % (rec.count(),))
    for item in rec:
        del item["_id"]
        recs.append(item)
    return recs


def remove_domain_from_mongo(domain_2nd, sub_domain, db, mongo_index):
    """
    移除以domain_2nd为键， sub_domain为值的记录,sub_domain可能存在于sub_domains或者ver_sub_domains中
    如：
    :param domain_2nd:
    :param sub_domain:
    :return:
    """
    query_body = {DOMAIN_2ND_FIELD: domain_2nd}
    basic_body = {"$pull": {SUBDOMAINS_FIELD: sub_domain, VER_SUBDOMAINS_FIELD: sub_domain}}
    db[mongo_index].update(query_body, basic_body)


def delete_mistaken_matches(domain_bad, db, mongo_index):
    """
    删除search中的伪匹配：如，domain_2nd:x.gg匹配到了xzgg-gov-cn.cname.saaswaf.com
    :param domain_bad:
    :param db:
    :param mongo_index:
    :return:
    """
    recs = get_niclog_domains(domain_bad)
    for rec in recs:
        domain_2nd, sub_domains, ver_sub_domains = split_domain_rec(rec)
        for sub_domain in sub_domains:
            # 伪匹配
            domain_2nd = domain_2nd.lower()
            sub_domain = sub_domain.lower()
            pos = sub_domain.find(domain_2nd)
            cond1 = pos > 0 and sub_domain[pos - 1] != '.'
            if cond1 or pos < 0:
                print("mistaken domain: %s, sub_domain: %s" % (domain_2nd, sub_domain))
                remove_domain_from_mongo(domain_2nd, sub_domain, db, mongo_index)


def save_mal_domains2mongodb(db, mongo_index, domain_2nd, sub_domains):
    db[mongo_index].update({"domain": domain_2nd},
                           {"$addToSet": {"ver_mal_sub_domains": {"$each": sub_domains}}}, True)


def read_not_mal_domains_file(file):
    """
     从文件中读取非恶意的域名
    :param file:
    :return:
    """
    not_mal_domains = set()
    with open(file) as f_out:
        for line in f_out.readlines():
            domain_2nd = line.strip("\n")
            not_mal_domains.add(domain_2nd)
    return list(not_mal_domains)


def delete_not_mal_domain(domain_2nd, db, mongo_index):
    """
    删除不是恶意域名的记录
    :param domain_2nd:
    :param db:
    :param mongo_index:
    :return:
    """
    query_body = {DOMAIN_2ND_FIELD: domain_2nd}
    db[mongo_index].delete_one(query_body)


def delete_not_mal_domains(db, domain_bad, file):
    """
    删除验证后并非恶意域名的域名
    :param db:
    :param domain_bad:
    :param file:
    :return:
    """
    mongo_index = mongo_index_dict[domain_bad]
    not_mal_domains = read_not_mal_domains_file(file)
    print('len of not mal doms: %s' % (len(not_mal_domains)))
    for domain_2nd in not_mal_domains:
        # print("delete domain: %s" % (domain_2nd))
        delete_not_mal_domain(domain_2nd, db, mongo_index)


def delete_not_visited_domains(db, domain_bad):
    """由于伪匹配会导致匹配到一些未访问过的域名，这里删除这些域名"""
    mongo_index = mongo_index_dict[domain_bad]
    query_body = {SUBDOMAINS_FIELD: {"$size": 0}}
    num = db[mongo_index].find(query_body).count()
    print("before delete not visited domains, there are: %s domains not visited" % (num,))
    # db[mongo_index].delete_many(query_body)
    num = db[mongo_index].find().count()
    print("after delete not visited domains, there are: %s domains" % (num,))


def delete_not_visited_domains_v1(db, domain_bad, old_domain_set):
    """
    从bad_full_domains_visiting_records或good_full_domains_visiting_records中查找访问过的二级域名
    :param db:
    :param domain_bad:
    :param old_domain_set: 从Niclog中匹配的二级域名，存在bad_domain_subdomain中
    :return:
    """
    mongo_index = visiting_mongo_index_dict[domain_bad]
    recs = db[mongo_index].find()
    domain_2nd_set = set()
    for rec in recs:
        full_domain = rec[FULL_DOMAIN]
        domain_2nd = keep_2nd_dom_name(full_domain)
        domain_2nd_set.add(domain_2nd)
    domain_2nd_set = domain_2nd_set & old_domain_set
    print("len of visited domain_2nd: %s" % (len(domain_2nd_set)))


def delete_not_formated_domains(db, domain_bad):
    """
    由于之前没有处理，很多二级域名和三级子域名未转成小写就直接存入了mongodb，现在将它们转成小写后在 存入mongodb中
    这里先删除之前的，大写域名，并将相应的小写形式存回mongodb
    """
    mongo_index = mongo_index_dict[domain_bad]
    recs = get_niclog_domains(domain_bad)
    for domain_dict in recs:
        domain_2nd = domain_dict[DOMAIN_2ND_FIELD]
        if domain_2nd != domain_2nd.lower():
            print("domain_2nd:%s, domain_2nd.lower(): %s" % (domain_2nd, domain_2nd.lower()))
            query_body = {DOMAIN_2ND_FIELD: domain_2nd}
            basic_body = {"$set": {DOMAIN_2ND_FIELD: domain_2nd.lower()}}
            db_nic_sub_domains[mongo_index].update(query_body, basic_body)
            continue
        sub_domains = domain_dict.get(SUBDOMAINS_FIELD, [])
        sub_domains_lower = [keep_3th_dom_name(item) for item in sub_domains]
        ver_sub_domains = domain_dict.get(VER_SUBDOMAINS_FIELD, [])
        for sub_domain, domain_3th in zip(sub_domains, sub_domains_lower):
            # 当存入数据库中的子域名不是三级子域名
            con1 = len(sub_domain) > len(domain_3th)
            con2 = sub_domain != domain_3th
            if con1 or con2:
                print("not subdomain, sub_domain: %s, domain_3th: %s" % (sub_domain, domain_3th))
                remove_domain_from_mongo(domain_2nd, sub_domain, db_nic_sub_domains, mongo_index)
                db[mongo_index].update({DOMAIN_2ND_FIELD: domain_2nd}, {"$addToSet": {SUBDOMAINS_FIELD: domain_3th}},
                                       True)
                db[mongo_index].update({DOMAIN_2ND_FIELD: domain_2nd},
                                       {"$addToSet": {VER_SUBDOMAINS_FIELD: domain_3th}}, True)


def test_mal_domains(db, domain_bad, recs):
    # query_body = {"ver_mal_sub_domains": {"$exists": False}}
    mongo_index = mongo_index_dict[domain_bad]
    notmal_count, iter = 0, 0
    not_mal_domains = []
    for iter, domain_dict in enumerate(recs):
        domain_2nd = domain_dict[DOMAIN_2ND_FIELD]
        sub_domains = domain_dict[SUBDOMAINS_FIELD]
        ver_sub_domains = domain_dict.get(VER_SUBDOMAINS_FIELD, [])
        print("handlering %s domain %s" % (iter, domain_2nd))

        if scan_url(domain_2nd):
            sub_domains = list(set(sub_domains) - set(ver_sub_domains))
            for sub_domain in sub_domains:
                # 如果三级子域名和二级域名相同，则不必检测，直接认定该三级子域名相同。
                if sub_domain == domain_2nd:
                    continue
                if not scan_url(sub_domain):
                    sub_domains.remove(sub_domain)
                    print("domain_2nd: %s, sub_domain: %s" % (domain_2nd, sub_domain))
            save_mal_domains2mongodb(db, mongo_index, domain_2nd, sub_domains)
        else:
            # print("delete_not_mal_domain: %s" % (domain_2nd,))
            # delete_not_mal_domain(domain_2nd, db, mongo_index)  # 误判的恶意域名,不能直接删除，有时会将恶意域名看做是正常的
            not_mal_domains.append(domain_2nd)
            notmal_count += 1

    if notmal_count:
        print("notmal_count: %s" % (notmal_count,))
    # 将非恶意域名写入文件中，后面删除
    write2file(NOT_MAL_DOM_FILE, not_mal_domains)


def split_domain_rec(domain_dict):
    """
    将MongoDB数据中的每一条记录（一个字典）分割成各个字段
    :param domain_dict:
    :return:
    """
    domain_2nd = domain_dict[DOMAIN_2ND_FIELD]
    sub_domains = domain_dict[SUBDOMAINS_FIELD]
    ver_sub_domains = domain_dict.get(VER_SUBDOMAINS_FIELD, [])
    return domain_2nd, sub_domains, ver_sub_domains


def count_radio_of_bad_subdomains(domain_bad):
    """
    :param mal_domain_dict: 恶意二级域名的子域名中能够被验证的三级域名占所有子域名的比例
    :return:
    """
    recs = get_niclog_domains(domain_bad)
    ratio_dict = {}
    ratio_dict_list = []
    zero_count = 0
    for domain_dict in recs:
        domain_2nd, sub_domains, ver_sub_domains = split_domain_rec(domain_dict)
        try:
            ratio = len(ver_sub_domains) / len(sub_domains)
        except Exception as e:
            print("domain: %s, error: %s" % (domain_2nd, e))
            ratio = 0.0
        ratio_dict[domain_2nd] = ratio
        ratio_dict = {
            DOMAIN_2ND_FIELD: domain_2nd, SUBDOMAINS_NUMBER: len(sub_domains),
            VER_SUBDOMAINS_NUMBER: len(ver_sub_domains), VER_RATIO: ratio
        }
        ratio_dict_list.append(ratio_dict)
        if ratio == 0.0:
            print("domain: %s: ratio: %s, len(sub_domains): %s" % (domain_2nd, ratio, len(sub_domains)))
            zero_count += 1

    print("generate %s" % (BAD_RATIO_FILE))
    remove_file(BAD_RATIO_FILE)
    df = pd.DataFrame(ratio_dict_list, columns=[DOMAIN_2ND_FIELD, SUBDOMAINS_NUMBER, VER_SUBDOMAINS_NUMBER, VER_RATIO])
    df.sort_values(by=VER_RATIO)
    df.to_csv(BAD_RATIO_FILE)
    return ratio_dict


def cmp_func(real_val, lower_bound, op):
    """
    :param real_val: 真实值
    :param lower_bound: 下界
    :param op:
        为0时，表示是否real_val == lower_bound；
        为1时，是否real_val > lower_bound；
        为-1时，是否real_val < lower_bound
    :return:
    """
    diff = real_val - lower_bound
    if op == 0:
        return diff == 0
    elif op == 1:
        return diff > 0
    return diff < 0


def read_csv_with_fields(csv_file, cmp_func):
    """
    从BAD_RATIO_FILE中找出bad_ratio=len(subdomains)/len(ver_sub_domains) < 0.8且len(subdomains)>2的恶意域名
    """
    # if df.loc[i][VER_RATIO] < BAD_RATIO_THRESHOLD and df.loc[i][SUBDOMAINS_NUMBER] > SUBDOMAIN_NUMBER_THRESHOLD:

    ans_list = []
    df = pd.read_csv(csv_file)
    for i in range(len(df)):
        # bad_ratio < 0.8 且len(subdomains) > 0
        if cmp_func(df.loc[i][VER_RATIO], BAD_RATIO_THRESHOLD, -1) and cmp_func(df.loc[i][SUBDOMAINS_NUMBER],
                                                                                SUBDOMAIN_NUMBER_THRESHOLD, 1):
            # bad_ratio < 0.8 且 len(subdomains) > 2
            # if cmp_func(df.loc[i][VER_RATIO], BAD_RATIO_THRESHOLD, -1) and cmp_func(df.loc[i][SUBDOMAINS_NUMBER],
            #                                                                             SUBDOMAIN_NUMBER_THRESHOLD, 1):
            print("domain: %s, ratio: %s, subdomain_numbers: %s" % (
                df.loc[i][DOMAIN_2ND_FIELD], df.loc[i][VER_RATIO], df.loc[i][SUBDOMAINS_NUMBER]))
            ans_list.append(df.loc[i][DOMAIN_2ND_FIELD])
    return ans_list


def get_low_bad_ratio_domains_from_csv(csv_file, cmp_func):
    """
    从BAD_RATIO_FILE中找出bad_ratio=len(subdomains)/len(ver_sub_domains) < 0.8且len(subdomains)>2的恶意域名
    """
    ans_list = []
    df = pd.read_csv(csv_file)
    for i in range(len(df)):
        if cmp_func(df.loc[i][VER_RATIO], BAD_RATIO_ZERO, 0):
            # print("domain: %s, ratio: %s, subdomain_numbers: %s" % (
            #     df.loc[i][DOMAIN_2ND_FIELD], df.loc[i][VER_RATIO], df.loc[i][SUBDOMAINS_NUMBER]))
            ans_list.append(df.loc[i][DOMAIN_2ND_FIELD])
    return ans_list


def domain_has_low_bad_ratio(domain):
    low_ratio_domains = get_low_bad_ratio_domains_from_csv(BAD_RATIO_FILE, cmp_func)
    if domain in low_ratio_domains:
        return True
    return False


def test_low_bad_ratio_domains(domain_bad):
    """验证，bad_ratio=len(subdomains)/len(ver_sub_domains) < 0.8且len(subdomains)>2的恶意域名"""
    domains = read_csv_with_fields(BAD_RATIO_FILE, cmp_func)
    print("there are %s domains has low bad ratio" % (len(domains)))
    for iter, domain in enumerate(domains):
        print("handlering %s domain %s" % (iter, domain))
        query_body = {DOMAIN_2ND_FIELD: domain}
        recs = get_niclog_domains(domain_bad, query_body)
        test_mal_domains(db_nic_sub_domains, domain_bad, recs)


def delete_some_domains(domain_bad):
    """由于历史原因，niclog访问集合中存在一些不正确的域名
    删除伪匹配的恶意域名，未格式化的恶意域名，并非恶意的域名
    """
    delete_mistaken_matches(domain_bad, db_nic_sub_domains, mongo_index_dict[domain_bad])
    delete_not_formated_domains(db_nic_sub_domains, domain_bad)
    delete_not_visited_domains(db_nic_sub_domains, domain_bad)

    # 正常域名，尚且无法支持此条
    if domain_bad:
        delete_not_mal_domains(db_nic_sub_domains, domain_bad, NOT_MAL_DOM_FILE)


if __name__ == "__main__":
    domain_bad = int(input("please enter a number: 0 for good domains, 1 for bad domains"))
    # delete_some_domains(domain_bad)

    # 验证所有从niclog中找到的恶意域名
    # recs = get_niclog_domains(domain_bad)
    # test_mal_domains(db_nic_sub_domains, domain_bad, recs)

    # 计算每个域名的恶意子域名的占比,并重新查询那些恶意子域名较少的二级域名
    # count_radio_of_bad_subdomains(domain_bad)
    # test_low_bad_ratio_domains(domain_bad)

    # 删除未访问过的域名：实验证明很多域名确实出现在了niclog中，那么为什么count中无法匹配呢？
    # old_domain_set = set()
    # for rec in recs:
    #     domain_2nd = rec[DOMAIN_2ND_FIELD]
    #     old_domain_set.add(domain_2nd)
    # delete_not_visited_domains_v1(db_nic_sub_domains, domain_bad, old_domain_set)
