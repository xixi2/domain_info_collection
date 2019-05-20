import pandas as pd
from pymongo import MongoClient

from common.mongodb_op import MAL_DOMS_MONGO_DB, GOOD_DOMAINS_MONGO_DB, DOMAIN_WHOIS_MONGO_INDEX
from common.common_whois_fields import CREATE_DATE, UPDATE_DATE, EXPIRY_DATE, VALID_DURATION
from common.mongo_common import DOMAIN_2ND_FIELD
from common.mongodb_op import mongo_url

client = MongoClient(mongo_url)
db_whois_bad = client[MAL_DOMS_MONGO_DB]
db_whois_good = client[GOOD_DOMAINS_MONGO_DB]
BAD_WHOIS_FILE = "bad_whois.csv"
GOOD_WHOIS_FILE = "good_whois.csv"
whois_file_dict = {
    0: GOOD_WHOIS_FILE,
    1: BAD_WHOIS_FILE
}
db_dict = {
    0: db_whois_good,
    1: db_whois_bad
}


def get_whois_info(domain_bad):
    db_whois = db_dict[domain_bad]
    mongo_index = DOMAIN_WHOIS_MONGO_INDEX
    recs = db_whois[mongo_index].find()
    date_dict_list = []
    for rec in recs:
        domain = rec[DOMAIN_2ND_FIELD]
        create_date = rec.get(CREATE_DATE, None)
        expiry_date = rec.get(EXPIRY_DATE, None)
        update_date = rec.get(UPDATE_DATE, None)
        if create_date:
            print("domain: %s, create_date:%s" % (domain, create_date))
            if expiry_date:
                print("nont create_date:%s, expiry_date:%s" % (create_date, expiry_date))

        if create_date and expiry_date:
            print(domain)
            valid_duration = expiry_date - create_date
            date_dict = {DOMAIN_2ND_FIELD: domain, VALID_DURATION: valid_duration}
            date_dict_list.append(date_dict)
    df = pd.DataFrame(date_dict_list, columns=[DOMAIN_2ND_FIELD, VALID_DURATION])
    file = whois_file_dict[domain_bad]
    df.to_csv(file, index=True)


if __name__ == '__main__':
    domain_bad = int(input("please enter what kind of domains to query from the logs:0 for good, 1 for bad"))

    get_whois_info(domain_bad)
