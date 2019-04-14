import tldextract
import re

PRE_DIR = "../data_set/bad_domains/"

FULL_DOM_DIR = "../data_set/bad_domains_txt/"  # 需要处理成二级或者三级域名的URL或者全限定域名
UVER_DOM_DIR = "../data_set/extracted_bad_domains/"  # 处理后的二级或者三级域名，尚未验证是否是恶意域名
VER_DOM_DIR = "../data_set/verified_bad_domains/"  # 验证后的恶意域名
UNVER_GOOD_DOM_DIR = "../data_set/good_domains/"

BAD_DOMAIN_FILE_2ND = "../data_set/domains2.txt"
BAD_DOMAIN_FILE_3TH = "../data_set/domains3.txt"


def keep_2nd_dom_name(domain_name):
    """
    只保留两层域名
    :param domain_name:
    :return:
    """
    sub_domain, domain, suffix = tldextract.extract(domain_name)
    return domain + "." + suffix


def keep_3th_dom_name(domain_name):
    """
    只保留两层域名
    :param domain_name:
    :return:
    """
    domain_name = domain_name.lower()
    sub_domain, domain, suffix = tldextract.extract(domain_name)
    sub_domain_list = sub_domain.split(".")
    if len(sub_domain_list) > 1:
        sub_domain = sub_domain_list[-1]
    if sub_domain != "":
        new_domain = ".".join((sub_domain, domain, suffix))
    else:
        new_domain = ".".join((domain, suffix))
        # print("domain_name: %s, sub: %s, dom: %s, suffix: %s, new_domain: %s" % (domain_name, sub_domain, domain, suffix, new_domain))
    return new_domain


def write2file(file, domains_set):
    """
    将域名写入文件中
    :param file: 要写入的文件
    :param domains_set: 要写入文件的域名
    :return:
    """
    with open(file, "a+") as f_in:
        for domain in domains_set:
            line = domain + "\n"
            f_in.write(line)


def read_domain_file(file):
    domains = set()
    with open(file) as f_out:
        lines = f_out.readlines()
        for line in lines:
            domain = line.strip("\n").lower()

            # 暂时再加上一层过滤，防止域名不是二级域名
            domain_2nd = keep_2nd_dom_name(domain)
            if len(domain) != len(domain_2nd):
                content = domain + "," + file.strip("\n")
                # print("content: %s" % content)
                continue
            domains.add(domain)
    print("read_domain_file: %s, len of domains: %s" % (file, len(domains)))
    return domains


def is_domain_ip(domain):
    # 检测域名是否是IP，如果是，返回None
    pattern = "[\d]+\.[\d]+\.[\d]+\.[\d]"
    if re.match(pattern, domain):
        return True
    else:
        return False
