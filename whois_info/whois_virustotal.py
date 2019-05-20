import requests
import random
import time
import copy
import pandas as pd
from datetime import datetime
from requests.adapters import HTTPAdapter
from pymongo import MongoClient

from common.scrawer_tools import WHOIS_URL, ERROR_SLEEP, API_KEYS, USER_AGENTS, HEADERS
from common.scrawer_tools import get_proxy_from_redis
from common.mongodb_op import query_mongodb_by_body, save_domain_subdomains2mongodb
from common.mongodb_op import MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, DOMAIN_IP_RESOLUTION_MONGO_INDEX, \
    DOMAIN_WHOIS_MONGO_INDEX, GOOD_DOMAINS_MONGO_DB, GOOD_DOMAINS_MONGO_INDEX, DOMAIN_WHOIS_MONGO_INDEX, \
    DOMAIN_SUBDOMAIN_MONGO_INDEX, DOMAIN_IP_RESOLUTION_MONGO_INDEX
from common.mongodb_op import mongo_url
from common.common_whois_fields import CREATE_DATE, UPDATE_DATE, EXPIRY_DATE, VALID_DURATION, REGISTRANT_COUNTRY, \
    ADMIN_COUNTRY, ADMIN_REGION, CATEGORIES
from common.mongo_common import DOMAIN_2ND_FIELD, SUBDOMAINS_FIELD
from common.date_op import change_date_str_format_v1, format_date_string, differate_one_day_more
from common.domains_op import keep_3th_dom_name, write2file
from get_visited_bad_domains_info.get_mal_domains_from_niclog import load_bad_niclog_domains
from common.domains_op import read_domain_file
from niclog_url.read_niclog_url_file import BAD_URL_DOMAINS_FILE, GOOD_URL_DOMAINS_FILE

client = MongoClient(mongo_url)
db_subdomain_bad = client[MAL_DOMS_MONGO_DB]
db_subdomain_good = client[GOOD_DOMAINS_MONGO_DB]
db_ip_good = client[GOOD_DOMAINS_MONGO_DB]
db_ip_bad = client[MAL_DOMS_MONGO_DB]
db_whois_good = client[GOOD_DOMAINS_MONGO_DB]
db_whois_bad = client[MAL_DOMS_MONGO_DB]
db_whois_dict = {0: db_whois_good, 1: db_whois_bad}
db_ip_dict = {0: db_ip_good, 1: db_ip_bad}
db_subdomain_dict = {0: db_subdomain_good, 1: db_subdomain_bad}

# 三个公共的集合名
ip_mongo_index = DOMAIN_IP_RESOLUTION_MONGO_INDEX
subdomain_mongo_index = DOMAIN_SUBDOMAIN_MONGO_INDEX
whois_mongo_index = DOMAIN_WHOIS_MONGO_INDEX

WHOIS_DAYS_GAP_FILE = "days_gap.csv"
ALIVE_DAYS = "alive_days"  # 从注册日到过期日的天数
UPDATE_DAYS = "update_days"  # 从上一次修改的日期到目前为止的天数
REGISTER_DAYS = "left_days"  # 从注册日到今日的天数


def get_whois_info(domain):
    """
    :param domain: 待检测的域名
    :return: 返回一个dict domain:被检测的域名 flag:该域名是否是恶意的
    """
    key_index = random.choice(range(0, len(API_KEYS)))
    api_key = API_KEYS[key_index]
    params = {"domain": domain, "apikey": api_key}

    while True:
        pro = get_proxy_from_redis()
        try:
            proxy = {'http': 'http://' + pro}
            user_agent = random.choice(USER_AGENTS)
            headers = copy.deepcopy(HEADERS)
            headers["User-Agent"] = user_agent
            s = requests.Session()
            s.mount('https://', HTTPAdapter(max_retries=1))
            s.keep_alive = False
            response = s.get(WHOIS_URL, params=params, headers=headers, timeout=5, proxies=proxy)
            # print(response.status_code)
            if response.status_code != 200:
                time.sleep(ERROR_SLEEP)
                return False
            print("pro: %s, url: %s, successfully get domain_name: %s" % (pro, response.url, domain))
            d = response.json()
            response.close()
            return d
        except Exception as e:
            # write_error_domains(domain)
            print("domain_name: %s, error: %s, pro: %s" % (domain, e, pro))
            time.sleep(ERROR_SLEEP)


def save_whois_info2mongodb(domain, whois_info, db, mongo_index=DOMAIN_WHOIS_MONGO_INDEX):
    """
    将whois信息插入到MongoDB数据库中，只查一次，若某个域名的whois信息已经存在，则不继续查询
    """
    query_body = {"domain": domain}
    if not db[mongo_index].find(query_body).count():
        db[mongo_index].insert(whois_info)


def get_old_whois_info(domain_bad, mongo_index=DOMAIN_WHOIS_MONGO_INDEX):
    """
    正常域名和恶意域名都有DOMAIN_WHOIS_MONGO_INDEX：domain_whois集合
    """
    rec = db_whois_dict[domain_bad][mongo_index].find()
    domain_set = set()
    for item in rec:
        domain = item["domain"]
        domain_set.add(domain)
    return domain_set


def save_domain_ip_resolutions2mongodb(domain, ips, db, mongo_index=DOMAIN_IP_RESOLUTION_MONGO_INDEX):
    # 如何做到不适用for循环一次向一个数组中添加多个元素: addtoset与each结合
    db[mongo_index].update({"domain": domain}, {"$addToSet": {"ips": {"$each": ips}}}, True)


def set_categories(domain_info):
    """
    从domain_info字典中取出域名对应的categories
    :param domain_info:
    :return:
    """
    bitdefender_category = domain_info.get("BitDefender category", None)  # 网站类别，如portals为门户网站
    alexa_category = domain_info.get("Alexa category", "")
    trend_micro_category = domain_info.get("TrendMicro category", None)
    categories = []
    if bitdefender_category:
        categories.append(bitdefender_category)
    if alexa_category:
        categories.append(alexa_category)
    if trend_micro_category:
        categories.append(trend_micro_category)
    return categories


def set_whois_info_dict(domain, whois_sentence, categories):
    """
    :param whois_sentence: str，是获取到的whois文本
    :param categories: 域名的categories
    :return:
    """
    print("type of whois_info : %s" % type(whois_sentence))
    if whois_sentence:
        whois_list = whois_sentence.split("\n")
        whois_dict = {item.split(":")[0]: ''.join(item.split(":")[1:]) for item in whois_list}
        create_date = whois_dict.get("Creation Date", None)  # 注册日期
        update_date = whois_dict.get("Updated Date", None)  # 更新日期
        expiry_date = whois_dict.get("Expiry Date", None)  # 过期日期
        registrant_country = whois_dict.get("Registrant Country", None)  # 注册国家
        admin_country = whois_dict.get("Admin Country", "")  # 管理国家
        admin_region = whois_dict.get("Admin State/Province", "")  # state或者province

        whois_info = {DOMAIN_2ND_FIELD: domain}
        if create_date:
            whois_info[CREATE_DATE] = change_date_str_format_v1(create_date)
        if update_date:
            whois_info[UPDATE_DATE] = change_date_str_format_v1(update_date)
        if expiry_date:
            whois_info[EXPIRY_DATE] = change_date_str_format_v1(expiry_date)
        if registrant_country:
            whois_info[REGISTRANT_COUNTRY] = registrant_country.lower()
        if admin_country:
            whois_info[ADMIN_COUNTRY] = admin_country.lower()
        if admin_region:
            whois_info[ADMIN_REGION] = admin_region.lower()
        if categories:
            whois_info[CATEGORIES] = categories
        return whois_info
    return {}


def save_subdomain_and_ip2database(domain, domain_info, domain_bad):
    db_ip = db_ip_dict[domain_bad]
    db_subdomain = db_subdomain_dict[domain_bad]
    subdomains = domain_info.get(SUBDOMAINS_FIELD, [])  # 子域名
    resolution_ips = [keep_3th_dom_name(item.get("ip_address")) for item in domain_info.get("resolutions", [])]
    if subdomains:
        save_domain_subdomains2mongodb(domain, subdomains, db_subdomain, subdomain_mongo_index)
    if resolution_ips:
        save_domain_ip_resolutions2mongodb(domain, resolution_ips, db_ip, ip_mongo_index)


def save_whois_info2database(domain, domain_info, domain_bad):
    """将域名的whois信息存入mongodb中"""
    db_whois = db_whois_dict[domain_bad]
    categories = set_categories(domain_info)
    whois_info = domain_info["whois"]
    whois_info_dict = set_whois_info_dict(domain, whois_info, categories)
    if len(whois_info_dict) > 1:  # 只有至少找到了与该域名相关的某个信息，如create_date之后才插入数据库
        print("=============================================================================")
        print("whois_info_dict: ", whois_info_dict)
        print("=============================================================================")
        save_whois_info2mongodb(domain, whois_info_dict, db_whois, whois_mongo_index)


def resolve_whois_info(domain, domain_bad):
    """
    正常域名和恶意域名都有：domain_ips，domain_subdomains，domain_whois这三个集合
    """
    domain_info = get_whois_info(domain)
    assert isinstance(domain_info, dict)  # 请求结果可能为False
    if domain_info["response_code"] == 0:  # 请求成功，但是域名不在virustotal数据库中
        print("%s" % (domain_info["verbose_msg"]))
        return
    save_whois_info2database(domain, domain_info, domain_bad)
    # save_subdomain_and_ip2database(domain, domain_info, domain_bad)


def get_all_domains(domain_bad):
    """
    从域名数据集中取出所有需要查询的域名
    :param domain_bad:
    :return:
    """
    if domain_bad:  # 取出mongodb中所有的恶意域名
        domain_list = query_mongodb_by_body(client, MAL_DOMS_MONGO_DB, MAL_DOMS_MONGO_INDEX, fields)
    else:  # 从mongodb中取出所有的正常域名
        domain_list = query_mongodb_by_body(client, GOOD_DOMAINS_MONGO_DB, GOOD_DOMAINS_MONGO_INDEX, fields)
    return domain_list


def days_gap2csv(data_dict, columns, domain_bad):
    df = pd.DataFrame(data_dict, columns=columns)
    file = str(domain_bad) + "_" + WHOIS_DAYS_GAP_FILE
    df.to_csv(file, index=True)


def count_alive_days(domain_list, domain_bad):
    """
    统计域名的存活时间，从注册日到当前日期；和域名的最近修改时间
    并写入csv文件中
    :param domain_list:
    :param domain_bad:
    :return:
    """
    db = db_whois_dict[domain_bad]
    data_dict_list = []
    time_format = "%Y%m%d"
    today = datetime.now().strftime(time_format)
    for domain in domain_list:
        print("=================================================")
        print("domain: %s" % (domain))
        query_body = {DOMAIN_2ND_FIELD: domain}
        recs = db[whois_mongo_index].find(query_body)
        print("recs.count(): %s" % recs.count())
        if recs.count() > 0:
            rec = recs[0]
            create_date = rec.get(CREATE_DATE, "")
            update_date = rec.get(UPDATE_DATE, "")
            expiry_date = rec.get(EXPIRY_DATE, "")
            try:
                print("creat_date: %s, update_date: %s, expiry_date: %s" % (
                    len(create_date), len(update_date), len(expiry_date)))
                print("creat_date: %s, update_date: %s, expiry_date: %s" % (create_date, update_date, expiry_date))
                # create_date = format_date_string(create_date) if len(create_date) > 0 else today
                if len(create_date) > 0:
                    create_date = format_date_string(create_date)
                else:
                    create_date = today

                # update_date = format_date_string(update_date) if len(update_date) > 0 else today
                if len(update_date) > 0:
                    update_date = format_date_string(update_date)
                else:
                    update_date = today
                # expiry_date = format_date_string(expiry_date) if len(expiry_date) > 0 else today
                if len(expiry_date) > 0:
                    expiry_date = format_date_string(expiry_date)
                else:
                    expiry_date = today

                print("12232 create: ", create_date, " expiry_date: ", expiry_date, " update: ", update_date)

                days_gap1 = differate_one_day_more(create_date, today) + 1
                days_gap2 = differate_one_day_more(update_date, today) + 1
                days_gap3 = differate_one_day_more(create_date, expiry_date) + 1
                print("days_gap1:%s, days_gap2: %s, days_gap3: %s" % (days_gap1, days_gap2, days_gap3))

                # 信息不全，如果days_gap1、days_gap2、days_gap3都为0，则说明三者信息都不足，则忽略此域名
                if days_gap1 or days_gap2 or days_gap3:
                    data_dict_list.append({
                        DOMAIN_2ND_FIELD: domain, REGISTER_DAYS: days_gap1, UPDATE_DAYS: days_gap2,
                        ALIVE_DAYS: days_gap3
                    })
            except Exception as e:
                print("error: ", e)
    columns = [DOMAIN_2ND_FIELD, REGISTER_DAYS, ALIVE_DAYS, UPDATE_DAYS]
    days_gap2csv(data_dict_list, columns, domain_bad)


def query_domain_whois(domain_list):
    domain_old_set = get_old_whois_info(domain_bad)  # 剔除已经获取了whois信息的域名

    # 获取已经成功取得whois信息的正常域名
    already_domains = domain_old_set & set(domain_list)
    print("already check %s domains" % (len(already_domains)))

    domain_list = list(set(domain_list) - domain_old_set)
    print("len of domain_list: %s" % (len(domain_list, )))
    for iter, domain in enumerate(domain_list):
        print("handlering %s domain: %s" % (iter, domain))
        try:
            if domain_bad:
                resolve_whois_info(domain, domain_bad)
            else:
                resolve_whois_info(domain, domain_bad)
        except AssertionError as e:
            print("AssertionError: %s" % (e,))


if __name__ == "__main__":
    domain_bad = int(input("please a number: 0 for collect whois of good domains, 1 for collect whois of bad domains"))
    fields = [DOMAIN_2ND_FIELD]

    # domain_list = get_all_domains(domain_bad)
    # print("before len of domain_list: %s" % (len(domain_list, )))

    # =================================================================
    # 临时直接查询所有可以形成时间序列的域名
    # from time_features.extract_time_seq2csv import get_visited_domains
    # domain_list = get_visited_domains(domain_bad)

    # 临时直接查询所有从niclog中找到的恶意域名
    # domain_list = load_bad_niclog_domains()

    # 临时直接查询所用从恶意域名数据集2中找到的498个恶意域名:记得删除
    # domain_list = read_domain_file(BAD_URL_DOMAINS_FILE)

    # 临时查询用于正常域名数据集的600个正常域名：记得删除
    # domain_list = read_domain_file(GOOD_URL_DOMAINS_FILE)
    # =================================================================

    # 若为恶意域名，则从BAD_URL_DOMAINS_FILE中读取，否则从GOOD_URL_DOMAINS_FILE读取
    domain_list = read_domain_file(BAD_URL_DOMAINS_FILE) if domain_bad else read_domain_file(GOOD_URL_DOMAINS_FILE)

    # 提取whois特征，并写入csv文件
    count_alive_days(domain_list, domain_bad)

    # query_domain_whois(domain_list)
