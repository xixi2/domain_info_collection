import os
from common.domains_op import read_domain_file
from common.other_common import remove_file
from common.mongodb_op import GOOD_DOMAINS_MONGO_DB, GOOD_DOMAINS_MONGO_INDEX
from common.mongodb_op import mongo_url
from pymongo import MongoClient

client = MongoClient(mongo_url)
db = client[GOOD_DOMAINS_MONGO_DB]

GOOD_DOMAINS_FILE = "../data_set/good_domains/alexa_2nd.txt"
MAL_DOMAINS_FILE = "../data_set/good_domains/checked_alexa_2nd.txt"
VER_GOOD_DOMAINS_FILE = "../data_set/good_domains/ver_alexa_2nd.txt"


def omit_bad_domains_from_alexa_domains():
    """
    原始的正常域名数据集中存在部分域名被virustotal认定是恶意的，
    这里是为了从原始的正常域名数据集中删除这些域名
    :return:
    """
    unchecked_domains = read_domain_file(GOOD_DOMAINS_FILE)
    bad_domains = read_domain_file(MAL_DOMAINS_FILE)
    good_domains = unchecked_domains - bad_domains
    print("len of good domains: %s" % (len(good_domains)))

    remove_file(VER_GOOD_DOMAINS_FILE)
    with open(VER_GOOD_DOMAINS_FILE, "a+") as f_in:
        for good_domain in good_domains:
            line = good_domain + "\n"
            f_in.write(line)


def save_good_domains2mongodb(file):
    with open(file) as f_out:
        for line in f_out.readlines():
            good_domain = line.strip("\n")
            print(good_domain)
            query_body = {"domain": good_domain}
            rec_counter = db[GOOD_DOMAINS_MONGO_INDEX].find(query_body).count()
            if not rec_counter:
                db[GOOD_DOMAINS_MONGO_INDEX].insert(query_body)


if __name__ == "__main__":
    omit_bad_domains_from_alexa_domains()
    save_good_domains2mongodb(VER_GOOD_DOMAINS_FILE)
