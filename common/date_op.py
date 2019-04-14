from datetime import datetime, timedelta


def generate_day_seq(start_day, day_range=1, date_format="%Y.%m.%d", forward=1):
    """
    获取100个如2018.10.01的日期字符串组成的列表
    :param date_format:
    :return:
    """
    dt_str_seq = []
    dt = datetime.strptime(start_day, date_format)
    for i in range(day_range):
        # print(dt.strftime(date_format))
        dt_str = dt.strftime(date_format)
        dt_str_seq.append(dt_str)
        dt = dt + timedelta(days=forward)
    return dt_str_seq


def change_date_str_format(date_str, origin_format="%Y.%m.%d", new_format="%Y%m%d"):
    dt = datetime.strptime(date_str, origin_format)
    dt_str = dt.strftime(new_format)
    return dt_str


def days_offset(date_str, day_range, date_format="%Y%m%d"):
    """
    日期向前或向后移动，当day_range为正，日期变大（未来），day_range为负，日期变小（过去）
    """
    dt = datetime.strptime(date_str, date_format)
    dt = dt + timedelta(days=day_range)
    dt_str = dt.strftime(date_format)
    return dt_str


def timestamp_str2ymdh(timestamp_str, date_format="%Y%m%d%H"):
    """把字符串类型的时间戳转换为年月日时组成的字符串，形如：2018100207"""
    timestamp_str = timestamp_str.split(".")[0]
    timestamp = int(timestamp_str)
    dt = datetime.fromtimestamp(timestamp)
    dt_str = dt.strftime(date_format)
    return dt_str


def differate_one_day_more(day_before, date_str, date_format="%Y%m%d"):
    """
    计算两个时间字符串之间相差天数
    :param day_before: 时间字符串2，其日期更靠近以前
    :param date_str: 时间字符串1，其日期更靠近现在
    :return:
        两个日期之间相差天数 -1 ，如"20190311"和"20190313"之间相差两天，则返回1
        这里大的含义是：更靠近未来
        当返回值大于等于0时，说明date_str比day_before大；
        当返回值等于-1时，date_str比day_before一样大；
        当返回值小于-1时，date_str比day_before小；
    """
    dt1 = datetime.strptime(date_str, date_format)
    dt2 = datetime.strptime(day_before, date_format)
    # print("dt1:%s, dt2: %s" % (dt1, dt2))
    days_gap = (dt1 - dt2).days
    # print("days_gap: %s" % (days_gap))
    return days_gap - 1


if __name__ == '__main__':
    days_gap = differate_one_day_more("20190311", "20190312")
    # days_gap = differate_one_day_more("20190310", "20190312")
    # days_gap = differate_one_day_more("20190313", "20190312")
    print("days_gap1111: %s" % (days_gap))
    # dt_str = change_date_str_format("2019.03.11")
    dt_str = days_offset("20190311", -1)
    print(dt_str)
