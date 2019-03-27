from pymongo import MongoClient

Host = '192.168.105.140'
Port = 27017
User = 'mongo123'
Password = 'mongo123'
database = 'test'

# mongo_url格式： mongodb://[username:password@]hostname[:port][/database]
# mongo_url = 'mongodb://%s:%s@%s:%s/%s' % (User, Password, Host, Port, database)
mongo_url = 'mongodb://%s:%s@%s:%s' % (User, Password, Host, Port)

# 恶意域名
MAL_DOMS_MONGO_DB = "malicious_domains"
MAL_DOMS_MONGO_INDEX = "mal_domains"
DOMAIN_IP_RESOLUTION_MONGO_INDEX = "domain_ips"
DOMAIN_SUBDOMAIN_MONGO_INDEX = "domain_subdomains"
DOMAIN_WHOIS_MONGO_INDEX = "domain_whois"
ACTIVE_MONGO_DB = "active_domain_ip_resolutions"
ACTIVE_DOM_TO_IP_MONGO_INDEX = "active_domain2ip"
ACTIVE_DOM_TTL_TO_MONGO_INDEX = "active_domain2ip_ttl"
ACTIVE_DOM_NAMESERVER_MONGO_INDEX = "active_domain2nameserver"
ACTIVE_DOM_NAMERSERVER_TTL_MONGO_INDEX = "active_domain2namerserver_ttl"
ACTIVE_NAMESERVER_TO_IP_MONGO_INDEX = "active_nameserver2ip"
ACTIVE_NAMERSER_TO_IP_TTL_MONGO_INDEX = "active_nameserver2ip_ttl"

# niclog访问记录
NIC_LOG_MONGO_DB = "nic_log_visiting"
NIC_LOG_FULL_NAME_VISITING_MONGO_INDEX = "full_domains_visiting_records"
NIC_LOG_GOOD_DOMAIN_SUBDOMAINS = "good_domain_subdomain"
NIC_LOG_GOOD_FULL_NAME_VISITING_MONGO_INDEX = "good_full_domains_visiting_records"


# 正常域名
GOOD_DOMAINS_MONGO_DB = "good_domains"
GOOD_DOMAINS_MONGO_INDEX = "good_domains"
GOOD_DOMAIN_IP_RESOLUTION_MONGO_INDEX = "domain_ips"
GOOD_DOMAIN_SUBDOMAIN_MONGO_INDEX = "domain_subdomains"
GOOD_DOMAIN_WHOIS_MONGO_INDEX = "domain_whois"


def query_mongodb_by_body(client, db_name, mongo_index, fields=None, query_body=None):
    recs_list = []
    db = client[db_name]
    if query_body:
        recs = db[mongo_index].find(query_body)
    else:
        recs = db[mongo_index].find()
    # print("files: %s" % fields)

    for item in recs:
        temp = []
        if fields:
            if len(fields) > 1:
                for field in fields:
                    temp.append(item[field])
                recs_list.append(tuple(temp))
            else:
                recs_list.append(item[fields[0]])
        else:
            temp = [val for key, val in item.items()]
            recs_list.append(tuple(temp))
    return recs_list


def save_domain_subdomains2mongodb(domain, subdomains, db, mongo_index=DOMAIN_SUBDOMAIN_MONGO_INDEX):
    """
    :param domain:
    :param subdomains:
    :return:
    """
    # 这里使用addset有问题，addset只能将一个元素加入到已有数组中，无法将多个元素加入到原始数组中
    db[mongo_index].update({"domain": domain}, {"$addToSet": {"subdomains": {"$each": subdomains}}}, True)


if __name__ == '__main__':
    client = MongoClient(mongo_url)  # 另一种方式：
    # client = MongoClient(Host, Port)

    # 选择数据库， 方式1，mongo_test是数据库名
    # db = client.mongo_test

    # 方式2
    db_name = "mongo_test"
    db = client[db_name]

    # 在mongodb中添加一个索引test_col，添加一条数据
    # post = {"name":"nancy","age":34}
    # col  = db.test_col
    # col.insert(post)

    # records = db.test_col.find({"name": "google"})  # 结果类型为<class 'pymongo.cursor.Cursor'>，支持for协议，可直接循环取出

    index_name = "test_col"
    records = db[index_name].find({"name": "google"})  # 结果类型为<class 'pymongo.cursor.Cursor'>，支持for协议，可直接循环取出
    print("records: %s" % (records))
    # print(records.count())  # records.count()输出所有结果条数
    # if not records.count():
    #     post = {"name": "google", "age": 31}
    #     col = db.test_col
    #     col.insert(post)

    # db[index_name].update({"name": "acva"}, {"$addToSet": {"weight": 7}, "$inc":{"aage": 1}}, True)
    db[index_name].update({"name": "acdadadd"}, {"$addToSet": {"weight": {"$each": [45]}}}, True)

    # 查询MongoDB数据库mongo_test中的所有索引
    # db_col_names = db.collection_names()
    # print("db_col_name: %s" % db_col_names)

    # 查询索引test_col中的所有记录
    records = db.test_col.find()  # 结果类型为<class 'pymongo.cursor.Cursor'>，支持for协议，可直接循环取出
    print("type: %s ,records: %s" % (type(records), records))
    for item in records:
        print(item)

    # db_name = "malicious_domains"
    # db = client[db_name]
    # # records = db.mal_domains.find()  # 结果类型为<class 'pymongo.cursor.Cursor'>，支持for协议，可直接循环取出
    # records = db["mal_domains"].find()  # 结果类型为<class 'pymongo.cursor.Cursor'>，支持for协议，可直接循环取出
    # print("type: %s ,records: %s" % (type(records), records))
    # print("count: %s" % (records.count()))
    # for item in records:
    #     print(item)
