"""
此文件是为了处理原始的恶意域名文件，这些文件中有一些额外字段，需要提取，处理这些原始域名文件后得到恶意域名数据集
"""
import os
import csv
import pandas as pd

from common.domains_op import is_domain_ip, keep_2nd_dom_name
from common.domains_op import PRE_DIR


def write2file(file, domains_set):
    with open(file, "a+") as f_in:
        for domain in domains_set:
            line = domain + "\n"
            f_in.write(line)


def write2csv(file, domain_list, domain_type):
    df = pd.DataFrame({"domain": domain_list, "type": domain_type})
    print(file)
    df.to_csv(file, index=True)


def csv2csv(file, url_col, time_col, type_col=-1, pattern="2019"):
    """
    把hosts_phishtank.csv文件转为txt文件
        src_file: 如src_file = ROOT_DIR + "/" + "hosts_phishtank.csv"
        dst_file: dst_file = ROOT_DIR + "/" + "hosts_phishtank.txt"
    :param file:
    :param time_row: 时间在csv文件中的列
    :param pattern:
    :return:
    """
    file_prefix = file.split(".")[0]
    src_file = PRE_DIR + file
    dst_file = PRE_DIR + file_prefix + "_simple_" + pattern + ".csv"
    dst_file1 = PRE_DIR + file_prefix + "_simple_" + pattern + ".txt"
    http_phrase = "http://"
    port_phrase = ":"
    domains_list, domains_type = [], []
    domain_2nd_list = []
    if not os.path.exists(src_file):
        return
    print("src_file: %s" % (src_file,))
    with open(src_file, "r") as f_out:
        f_csv = csv.reader(f_out)
        for row in f_csv:
            url = row[url_col]

            # 只要2019年的恶意域名记录
            find_time = row[time_col].strip(" ")
            if find_time[:len(pattern)].find(pattern) < 0:
                continue

            if url.find(http_phrase) >= 0:
                pos = url.find(http_phrase) + len(http_phrase)
                url = url[pos:]
                pos = url.find("/")
                if pos >= 0:
                    url = url[:pos]
                if not is_domain_ip(url):
                    # print("url %s, row[1]: %s" % (url, row[1]))
                    if url.find(port_phrase) >= 0:
                        pos = url.find(port_phrase)
                        url = url[:pos]
                    if url not in domains_list:
                        domains_list.append(url)

                        # 文件中不存在类型这一列，即文件为hosts_phishtank.csv，对应的type为钓鱼网站
                        if type_col == -1:
                            type = "phishing"
                        else:
                            type = row[type_col]
                        domains_type.append(type)

                        # 为了给二级域名添加响应的恶意类型时需要
                        domain_2nd_list.append(keep_2nd_dom_name(url))

    print("len of urls : %s, len of domains_info: %s" % (len(domains_list), len(domains_type)))
    write2csv(dst_file, domain_2nd_list, domains_type)
    write2file(dst_file1, domains_list)


if __name__ == '__main__':
    files = ["abuse.csv", "hosts_phishtank.csv"]
    pattern = "2017"
    csv2csv(files[0], 2, 1, 4)
    # csv2csv(files[1], 1, 3, -1, pattern)
