"""
从ES中查询域名的访问次数，形成时间序列存入到MongoDB中
"""
from datetime import datetime, timedelta
from elasticsearch import helpers, Elasticsearch
from pymongo import MongoClient

from get_visited_bad_domains_info.test_nic_mal_domains import get_niclog_domains
from common.date_op import timestamp_str2ymdh
from common.domains_op import keep_3th_dom_name, keep_2nd_dom_name
from common.mongodb_op import mongo_url
from common.mongodb_op import NIC_LOG_MONGO_DB, BAD_DOMAINS_COUNTER2ND_MONGO_INDEX, BAD_DOMAINS_COUNTER3TH_MONGO_INDEX, \
    GOOD_DOMAINS_COUNTER2ND_MONGO_INDEX, GOOD_DOMAINS_COUNTER3TH_MONGO_INDEX
from common.mongo_common import DOMAIN_2ND_FIELD, DOMAIN_3TH_FIELD, DATE_FIELD, SUBDOMAINS_FIELD, \
    VER_SUBDOMAINS_FIELD
from get_visited_bad_domains_info.query_bad_domain import get_domains_from_dataset_v1
from common.index_201_common import HOST, VIS_DOMAIN_INDEX_NAME_PREFIX, VIS_DOM_DOC_TYPE

PERIOD_START = '2018.04.10'  # 查询开始日期
# PERIOD_START = '2018.03.28'  # 查询开始日期
# DAY_RANGE = 7
# DAY_RANGE = 14
DAY_RANGE = 30  # 放松限制：不限制域名必须是被验证的恶意子域名
client = MongoClient(mongo_url)
db_nic_visiting = client[NIC_LOG_MONGO_DB]
bad_domain_counter2nd_mongo_index = str(DAY_RANGE) + "_" + BAD_DOMAINS_COUNTER2ND_MONGO_INDEX
bad_domain_counter3th_mongo_index = str(DAY_RANGE) + "_" + BAD_DOMAINS_COUNTER3TH_MONGO_INDEX
good_domain_counter2nd_mongo_index = str(DAY_RANGE) + "_" + GOOD_DOMAINS_COUNTER2ND_MONGO_INDEX
good_domain_counter3th_mongo_index = str(DAY_RANGE) + "_" + GOOD_DOMAINS_COUNTER3TH_MONGO_INDEX
domain_index_dict = {
    0: {2: good_domain_counter2nd_mongo_index, 3: good_domain_counter3th_mongo_index},
    1: {2: bad_domain_counter2nd_mongo_index, 3: bad_domain_counter3th_mongo_index}
}
WWW_PHREASE = "www."


def generate_day_seq(period_start, day_range, date_format="%Y.%m.%d"):
    """
    获取100个如2018.10.01的日期字符串组成的列表
    :param date_format:
    :return:
    """
    dt_str_seq = []
    dt = datetime.strptime(period_start, date_format)
    # for i in range(DAY_RANGE):        # 后面换成常量，现在使用参数
    for i in range(day_range):
        # print(dt.strftime(date_format))
        dt_str = dt.strftime(date_format)
        dt_str_seq.append(dt_str)
        dt = dt + timedelta(days=-1)
    return dt_str_seq


def tackle_domain(domain_dict):
    # 如果这个域名的子域名中被判断为恶意的个数为0，即该域名的bad ratio为0.0，就不查询这个域名
    # 使用的bac_ratio.txt文件需要手动更新
    # if domain_has_low_bad_ratio(domain_2nd):
    #     print("domain %s has low bad ratio" % (domain_2nd))
    #     return None,None, None
    domain_2nd = domain_dict[DOMAIN_2ND_FIELD].lower()
    sub_domains = domain_dict.get(SUBDOMAINS_FIELD, [])
    sub_domains = [item.lower() for item in sub_domains]
    ver_sub_domains = domain_dict.get(VER_SUBDOMAINS_FIELD, [])
    ver_sub_domains = [item.lower() for item in ver_sub_domains]
    return domain_2nd, sub_domains, ver_sub_domains


def count_domains_queries(domain_bad, day_range=7, period_start=PERIOD_START):
    """从mongodb中读取出niclog中出现过的恶意（或正常）域名，查询这些域名每个小时被查询的次数"""
    # recs = get_niclog_domains(domain_bad)
    recs = get_domains_from_dataset_v1(domain_bad)
    print("recs total len: %s" % (len(recs)))

    if domain_bad:
        start = 8000  # 下一次从8000开始
        batch_num = 1000
    else:
        start = 180  # 下次从180开始
        batch_num = 20
    # 因为一次无法处理完所有域名，所以分批出来
    recs = recs[start: min(batch_num + start, len(recs))]

    dt_str_seq = generate_day_seq(period_start, day_range)
    print("count_domains_queries for %s domains" % (len(recs)))
    es = Elasticsearch(hosts=HOST, timeout=10, sniff_on_start=True, sniff_on_connection_fail=True,
                       sniffer_timeout=60, sniff_timeout=10)
    doc_type = VIS_DOM_DOC_TYPE

    totally_matched = 0
    for domain_dict in recs:
        domain_matched_num = 0
        domain_2nd, sub_domains, ver_sub_domains = tackle_domain(domain_dict)
        for dt_str in dt_str_seq:
            index_name = VIS_DOMAIN_INDEX_NAME_PREFIX + dt_str
            # 若是恶意域名，则从niclog中匹配在ver_sub_domains列表中的恶意域名，
            # 若是正常域名，则从niclog中匹配在sub_domains列表中的正常域名
            if domain_bad:
                # matched = set_vis_bad_domain_index_params(es, doc_type, index_name, domain_2nd, ver_sub_domains,
                #                                           domain_bad)
                # matched = set_vis_bad_domain_index_params(es, doc_type, dt_str, domain_2nd, sub_domains, domain_bad)
                matched = set_vis_bad_domain_index_params_loose(es, doc_type, index_name, domain_2nd, ver_sub_domains,
                                                                domain_bad)
            else:
                matched = set_vis_bad_domain_index_params(es, doc_type, index_name, domain_2nd, sub_domains, domain_bad)
            domain_matched_num += 1 if matched else 0

            # 以后可以删除
            if matched:
                index_name = VIS_DOMAIN_INDEX_NAME_PREFIX + dt_str
                print('---------domain_2nd: {0}, index_name: {1}---------------'.format(domain_2nd, index_name))

        if domain_matched_num:
            totally_matched += 1
        else:
            print('---------domain_2nd: {0} missed---------------'.format(domain_2nd))
    print("totally matched %s domains" % (totally_matched))


def set_vis_bad_domain_index_params(es, doc_type, index_name, domain_2nd, ver_sub_domains, domain_bad):
    pattern = "([A-Za-z0-9-]?[A-Za-z0-9]+\.)?" + domain_2nd
    query_body = {"query": {"bool": {"must": [{"regexp": {"content": pattern}}, {"term": {"operation": "dnsquery3"}}]}}}

    # 是否匹配此域名
    matched = False
    if es.indices.exists(index_name):
        gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body, scroll='30m')
        for item in gen:
            item = item['_source']
            timestamp = item['time-stamp']
            dt_str = timestamp_str2ymdh(timestamp)
            index, dt_srt_day = int(dt_str[-2:]), dt_str[:-2]
            full_domain = item['content'].lower()
            domain_3th = keep_3th_dom_name(full_domain)

            # 完整域名中包含二级域名，且完整域名对应的二级域名在确认(正常或恶意的)子域名列表中
            # 三级域名就是二级域名本书(pos==0)，三级域名中包含这二级域名(pos>0)
            pos = domain_3th.find(domain_2nd)
            cond1 = pos > 0 and domain_3th[pos - 1] == '.' and domain_3th in ver_sub_domains
            cond2 = pos == 0 or domain_3th == WWW_PHREASE + domain_2nd

            # 为什么恶意域名匹配了那么多，却只有少数恶意域名出现在时间序列中
            con3 = pos > 0 and domain_3th[pos - 1] == '.'
            con4 = domain_3th in ver_sub_domains
            con5 = pos == 0 or domain_3th == WWW_PHREASE + domain_2nd
            print("full_domain: %s, domain_2nd: %s, con3: %s, con4:%s, con5: %s" % (
                full_domain, domain_2nd, con3, con4, con5))
            if con3 or con5:  # 此域名符合二级域名的要求，但不在验证过的三级域名中
                if not con4:
                    print("domain: %s is valid doamin_3th but not in ver_subdomains" % (domain_3th))

            if cond1 or cond2:
                print("domain_2nd: %s, domain_3th: %s, visit_day: %s" % (domain_2nd, domain_3th, dt_srt_day))
                mongo_query_body = {DOMAIN_2ND_FIELD: domain_2nd, DATE_FIELD: dt_srt_day}
                basic_body = {"$inc": {str(index): 1}}
                mongo_index_2nd = domain_index_dict[domain_bad][2]
                db_nic_visiting[mongo_index_2nd].update(mongo_query_body, basic_body, True)
                mongo_query_body = {DOMAIN_3TH_FIELD: domain_3th, DATE_FIELD: dt_srt_day, DOMAIN_2ND_FIELD: domain_2nd}
                basic_body = {"$inc": {str(index): 1}}
                mongo_index_3th = domain_index_dict[domain_bad][3]
                db_nic_visiting[mongo_index_3th].update(mongo_query_body, basic_body, True)

                matched = True
    return matched


def set_vis_bad_domain_index_params_loose(es, doc_type, index_name, domain_2nd, ver_sub_domains, domain_bad):
    pattern = "([A-Za-z0-9-]?[A-Za-z0-9]+\.)?" + domain_2nd
    query_body = {"query": {"bool": {"must": [{"regexp": {"content": pattern}}, {"term": {"operation": "dnsquery3"}}]}}}

    # 是否匹配此域名
    matched = False
    if es.indices.exists(index_name):
        gen = helpers.scan(es, index=index_name, doc_type=doc_type, query=query_body, scroll='30m')
        for item in gen:
            item = item['_source']
            timestamp = item['time-stamp']
            dt_str = timestamp_str2ymdh(timestamp)
            index, dt_srt_day = int(dt_str[-2:]), dt_str[:-2]
            full_domain = item['content'].lower()
            domain_3th = keep_3th_dom_name(full_domain)

            # 完整域名中包含二级域名，且完整域名对应的二级域名在确认(正常或恶意的)子域名列表中
            # 三级域名就是二级域名本书(pos==0)，三级域名中包含这二级域名(pos>0)
            pos = domain_3th.find(domain_2nd)
            cond1 = pos > 0 and domain_3th[pos - 1] == '.'
            cond2 = pos == 0 or domain_3th == WWW_PHREASE + domain_2nd

            # 为什么恶意域名匹配了那么多，却只有少数恶意域名出现在时间序列中
            cond4 = domain_3th in ver_sub_domains
            print("full_domain: %s, domain_2nd: %s, con3: %s, con4:%s, con5: %s" % (
                full_domain, domain_2nd, cond1, cond4, cond2))
            if cond1 or cond2:  # 此域名符合二级域名的要求，但不在验证过的三级域名中
                if not cond4:
                    print("domain: %s is valid doamin_3th but not in ver_subdomains" % (domain_3th))

            if cond1 or cond2:
                print("domain_2nd: %s, domain_3th: %s, visit_day: %s" % (domain_2nd, domain_3th, dt_srt_day))
                mongo_query_body = {DOMAIN_2ND_FIELD: domain_2nd, DATE_FIELD: dt_srt_day}
                basic_body = {"$inc": {str(index): 1}}
                mongo_index_2nd = domain_index_dict[domain_bad][2]
                db_nic_visiting[mongo_index_2nd].update(mongo_query_body, basic_body, True)
                mongo_query_body = {DOMAIN_3TH_FIELD: domain_3th, DATE_FIELD: dt_srt_day, DOMAIN_2ND_FIELD: domain_2nd}
                basic_body = {"$inc": {str(index): 1}}
                mongo_index_3th = domain_index_dict[domain_bad][3]
                db_nic_visiting[mongo_index_3th].update(mongo_query_body, basic_body, True)

                matched = True
    return matched


if __name__ == '__main__':
    # 统计每个域名在时间窗口内的DNS查询次数
    start = datetime.now()
    # count_domains_queries()
    domain_bad = int(input("please enter what kind of domains to query from the logs:0 for good, 1 for bad"))
    print("for defautlt the query starts from day: %s" % (PERIOD_START,))
    day_range = int(input("please enter how many days would you like to query, for default this is %s" % (DAY_RANGE)))
    count_domains_queries(domain_bad, day_range)
    end = datetime.now()
    time_cost = (end - start).seconds
    print("time_cost: %s" % time_cost)
