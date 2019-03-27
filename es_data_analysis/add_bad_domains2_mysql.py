# 这个文件是为了将从各个原始恶意域名数据集中提取出的规范的并且经过virustotal验证的恶意域名
# 存入到数据库mysql中
from common.mysql_config import DBSession
from es_data_analysis.model import BadDomains
from get_visited_bad_domains_info.hanlde_bad_domains import DST_DIR

session = DBSession()


def read_bad_domain_file(file):
    bad_domain_objs = []
    with open(file, "r") as f_out:
        for line in f_out.readlines():
            domain = line.strip("\n")
            bad_domain = BadDomains(domain_name=domain)
            # query = session.query(BadDomains).filter(bad_domain.domain_name==domain)
            # if not query.all():
            bad_domain_objs.append(bad_domain)
    session.add_all(bad_domain_objs)
    session.commit()


if __name__ == '__main__':
    choice = int(input("please enter 2 or 3, 2 for 2 level domain and 3 for 3 level domain:  "))
    file = DST_DIR + "v_domains" + str(choice) + ".txt"
    read_bad_domain_file(file)
