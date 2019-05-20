"""
这个文件是为了从alexa_top1m正常域名符串中提取特征，具体特征提取方法见：恶意域名字符串(pdf文件)
"""
import csv
from domain_name.domain_name_word_segment import word_segment, get_longest_meaningful_substring_v0
from common.database_op import connect_db, insert_db
from common.domains_op import keep_2nd_dom_name

conn = connect_db()

good_domain_table = "good_domains"


def extract2level_domain(good_domain):
    name_list = good_domain.split('.')
    # print('name_list: {0}'.format(name_list[-2]))
    return name_list[-2]


def save2database(domain_info_list):
    pass


def check_domains(domains, batch_num=50):
    domain_info_list = []
    i = 0
    for domain in domains:
        i += 1
        domain_2nd = keep_2nd_dom_name(domain)
        n_digits, digit_segs, word_segs = word_segment(domain_2nd)
        n_groups_of_digits = len(digit_segs)  # 整个二级域名字符串可以被多少组数字分隔开
        n_group_of_word_segs = len(word_segs)  # 整个二级域名中字符串最为被分为了多少组如w3cschool最后被分为三组：w, c,school
        longest_len, longest_substring = get_longest_meaningful_substring_v0(word_segs)  # 最长有意义字符串长度，最长有意义子串
        print('==============================================================')
        print('domain: {0}, domain_2nd: {1}, digit_segs: {2}, word_segs:{3}'
              .format(domain, domain_2nd, digit_segs, word_segs))
        print('domain_2nd: {0}, n_digits: {1}, n_groups_digits: {2}, n_group_word_segs: {3}'
              .format(domain_2nd, n_digits, n_groups_of_digits, n_group_of_word_segs))
        print('domain_2nd: {0}, longest_len:{1},longest_substring: {2}'
              .format(domain_2nd, longest_len, longest_substring))
        domain_info_list.append((domain, domain_2nd, n_digits, n_groups_of_digits, n_group_of_word_segs,
                                 longest_len, longest_substring))
        if i % batch_num == 0 or i == len(domains):
            save2database(domain_info_list)
            domain_info_list = []
            print('第{0}个域名正在统计'.format(i))


if __name__ == '__main__':
    domains = []
    check_domains(domains)
