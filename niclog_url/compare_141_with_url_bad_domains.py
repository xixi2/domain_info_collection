# 比较从niclog中找到的之前从niclog中匹配到的恶意域名数据集1中的恶意域名和从恶意域名数据集2中找到的恶意域名
from common.domains_op import read_domain_file, write2file
from get_visited_bad_domains_info.get_mal_domains_from_niclog import OLD_141_BAD_DOMAINS_FILE
from niclog_url.read_niclog_url_file import BAD_URL_DOMAINS_FILE, GOOD_URL_DOMAINS_FILE

if __name__ == "__main__":
    # old_141_domains = read_domain_file(OLD_141_BAD_DOMAINS_FILE)
    good_url_domains = read_domain_file(GOOD_URL_DOMAINS_FILE)
    nic_url_domains = read_domain_file(BAD_URL_DOMAINS_FILE)
    # insection_domains = set(old_141_domains) & set(nic_url_domains)
    insection_domains = set(good_url_domains) & set(nic_url_domains)
    good_url_domains = set(good_url_domains) - set(nic_url_domains)
    print("len of old bad domains found in nic url: %s" % len(insection_domains))
    for domain in insection_domains:
        print(domain)
