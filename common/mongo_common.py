DOMAIN_3TH_FIELD = "sub_domain"
DOMAIN_2ND_FIELD = "domain"
FULL_DOMAIN = "full_domain"
DATE_FIELD = "dt_str"
IP_FIELD = "ip"
IPS_FIELD = "ips"
SUBDOMAINS_FIELD = "subdomains"
VER_SUBDOMAINS_FIELD = "ver_mal_sub_domains"
SOURCE_SIET = "source"
MAL_TYPE = "type"
DOMAIN_STATUS = "status"  # 0表示域名不是恶意域名（经过检查以后），1表示域名是恶意域名, -1表示不确定域名是否恶意

# 域名与其子域名访问、恶意情况
SUBDOMAINS_NUMBER = "subdomain_numbers"
VER_SUBDOMAINS_NUMBER = "ver_subdomain_numbers"
VER_RATIO = "ratio"


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


def split_domain_rec_v1(domain_dict):
    """
    将MongoDB数据中的每一条记录（一个字典）分割成各个字段
    :param domain_dict:
    :return:
    """
    domain_2nd = domain_dict[DOMAIN_2ND_FIELD]
    status = domain_dict[DOMAIN_STATUS]
    return domain_2nd, status



