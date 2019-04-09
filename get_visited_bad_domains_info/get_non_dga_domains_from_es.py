"""
此文件是为了从ES索引malicious-domains中获取976个非DGA恶意域名
"""

from common.index_op_mal_dom import set_mal_domain_index_params, set_mal_domain_index_params1, get_domains_with_type
from common.domains_op import write2file
from common.domains_op import FULL_DOM_DIR, PRE_DIR


def write_domain_with_type_2file(file, domain_dict):
    with open(file, "a+") as f_in:
        for domain, info_tuple in domain_dict.items():
            source, mal_type = info_tuple[0], info_tuple[1]
            print("domain:%s, source: %s, mal_type: %s" % (domain, info_tuple[0], info_tuple[1]))
            line = domain + "," + source + "," + mal_type + "\n"
            f_in.write(line)


def get_non_dga_domains():
    query_body = {"query": {"bool": {"must_not": [{"query_string": {"default_field": "info.Desc", "query": "DGA"}}]}}}
    bad_domains = set_mal_domain_index_params(query_body)
    print("len of bad_domains: %s" % len(bad_domains))
    file = FULL_DOM_DIR + "es_non_dga.txt"
    write2file(file, bad_domains)

    # non dga域名及其来源和类型写入文件中
    file2 = PRE_DIR + "es_non_dga_with_type.txt"
    domain_dict = set_mal_domain_index_params1(get_domains_with_type, query_body)
    for domain, info_tuple in domain_dict.items():
        print("domain:%s, source: %s, mal_type: %s" % (domain, info_tuple[0], info_tuple[1]))
    write_domain_with_type_2file(file2, domain_dict)


if __name__ == '__main__':
    get_non_dga_domains()
