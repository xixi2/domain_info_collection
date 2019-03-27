

sql = """
select * from dns_answer GROUP BY ip HAVING count(*)>1;   # 查询映射到多个域名的ip
select * from dns_answer where ip in (select ip from dns_answer GROUP BY ip HAVING count(*)>1) ORDER BY ip;
# 查询这些ip对应的域名

select * from dns_answer GROUP BY domain_name HAVING count(*)>1;    # 查询映射到多个ip的域名
"""