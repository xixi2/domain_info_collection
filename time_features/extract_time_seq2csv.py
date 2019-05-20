"""
生成时间序列文件
分析提取出的访问频率，检测异常点
"""
import pandas as pd
from pymongo import MongoClient
from common.date_op import days_offset, differate_one_day_more, change_date_str_format
from common.mongodb_op import mongo_url
from common.other_common import remove_file
from common.mongodb_op import NIC_LOG_MONGO_DB, BAD_DOMAINS_COUNTER2ND_MONGO_INDEX, GOOD_DOMAINS_COUNTER2ND_MONGO_INDEX, \
    BAD_DOMAINS_COUNTER3TH_MONGO_INDEX
from time_features.count_bad_domains_visiting import DOMAIN_2ND_FIELD, DATE_FIELD, DAY_RANGE, PERIOD_START

TIME_SEQ_FIELD = "time_seq"
TIME_SEQ_FILE = TIME_SEQ_FIELD + ".csv"
client = MongoClient(mongo_url)
db_nic_visiting = client[NIC_LOG_MONGO_DB]
bad_domain_counter2nd_mongo_index = str(DAY_RANGE) + "_" + BAD_DOMAINS_COUNTER2ND_MONGO_INDEX
good_domain_counter2nd_mongo_index = str(DAY_RANGE) + "_" + GOOD_DOMAINS_COUNTER2ND_MONGO_INDEX

mongo_index_2nd_dict = {
    0: good_domain_counter2nd_mongo_index,
    1: bad_domain_counter2nd_mongo_index  # 后面加上时间长度，修改成这样
    # 0:GOOD_DOMAINS_COUNTER2ND_MONGO_INDEX,
    # 1: BAD_DOMAINS_COUNTER2ND_MONGO_INDEX
}


def csv2df(time_seq_file):
    """
    读取时间序列文件TIME_SEQ_FILE，返回一个dict，dict的键值是域名，每个值还是一个dict
    :return:
    """
    df = pd.read_csv(time_seq_file)
    time_seq_dict = {}
    for i in range(len(df)):
        # print("%s, %s" % (i, df.loc[i].values[1:]))
        domain_2nd = df.loc[i].values[1]
        date_str = df.loc[i].values[2]
        one_day_time_seq = df.loc[i].values[3:]  # one_day_time_seq 是ndarray
        # print(domain_2nd, len(one_day_time_seq), type(one_day_time_seq))
        if not time_seq_dict.get(domain_2nd):
            time_seq_dict[domain_2nd] = {}
        time_seq_dict[domain_2nd][date_str] = one_day_time_seq
    print("len(time_seq_dict): %s" % (len(time_seq_dict)))
    return time_seq_dict


def date_older_than_start_date(date_str):
    seq_start_date = days_offset(change_date_str_format(PERIOD_START), -1 * DAY_RANGE)
    if differate_one_day_more(seq_start_date, date_str) >= 0:
        return False
    return True


def date_younger_than_start_date(date_str):
    seq_end_date = change_date_str_format(PERIOD_START)
    if differate_one_day_more(seq_end_date, date_str) >= 0:
        return True
    return False


def get_visited_domains(domain_bad):
    """
    从MongoDB数据库中读出域名访问频率，形成时间序列，写入到csv文件
    :return:
    """
    mongo_index_2nd = mongo_index_2nd_dict[domain_bad]
    recs = db_nic_visiting[mongo_index_2nd].find()
    print("recs.count: %s" % recs.count())
    # 查看从日志中匹配到的可以形成时间的域名
    domains = set()
    for rec in recs:
        domain = rec[DOMAIN_2ND_FIELD]
        domains.add(domain)
    print("len of domains: %s" % (len(domains)))
    # for domain_2nd in domains:
    #     print("domain %s captured" % (domain_2nd))
    return list(domains)


def get_visiting_frequency(domain_bad, number):
    """
    从MongoDB数据库中读出域名访问频率，形成时间序列，写入到csv文件
    :return:
    """
    mongo_index_2nd = mongo_index_2nd_dict[domain_bad]
    recs = db_nic_visiting[mongo_index_2nd].find()

    if recs.count() > number:
        recs = recs[:number]

    print("get_visiting_frequency for %s domains" % (recs.count()))

    vis_dict_list = []
    for rec in recs:
        domain = rec[DOMAIN_2ND_FIELD]
        date_str = rec[DATE_FIELD]
        if date_older_than_start_date(date_str) or date_younger_than_start_date(date_str):
            print("date_str: %s" % (date_str))
            continue
        vis_dict = {
            DOMAIN_2ND_FIELD: domain,
            DATE_FIELD: date_str
        }
        for index in range(24):
            index_counter = rec.get(str(index), 0)
            vis_dict[index] = index_counter
        vis_dict_list.append(vis_dict)
    columns_fields = [DOMAIN_2ND_FIELD, DATE_FIELD]
    for index in range(24):
        columns_fields.append(index)
    df = pd.DataFrame(vis_dict_list, columns=columns_fields)
    df.sort_values(by=DOMAIN_2ND_FIELD).sort_values(by=DATE_FIELD)
    time_seq_file = str(domain_bad) + "_" + TIME_SEQ_FILE
    remove_file(time_seq_file)
    df.to_csv(time_seq_file, index=True)


if __name__ == '__main__':
    domain_bad = int(input("please enter what kind of domains to get: 0 for good doamins, 1 for bad domains"))
    number = 200  # 因为恶意域名和正常域名数量不一样，所以这里为了保持两种域名数量一致，设置number
    get_visited_domains(domain_bad)
    get_visiting_frequency(domain_bad, number)
    time_seq_file = str(domain_bad) + "_" + TIME_SEQ_FILE
    csv2df(time_seq_file)
