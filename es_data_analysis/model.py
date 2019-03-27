from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from common.mysql_config import DBSession, engine

Base = declarative_base()


class BadDomains(Base):
    __tablename__ = 'bad_domains'
    domain_name = Column(String(250), primary_key=True)
    # sld = Column(String(50), default="")
    # digit_numbers = Column(Integer, default=0)
    # digit_groups = Column(Integer, default=0)
    # word_groups = Column(Integer, default=0)
    # longest_len = Column(Integer, default=0)
    # longest_substring = Column(String(50), default="")


def create_table():
    Base.metadata.create_all(engine)


if __name__ == '__main__':
    session = DBSession()
    create_table()
