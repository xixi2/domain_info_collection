"""
将时间序列每天的相似度可视化
"""
import pandas as pd
import numpy as np

from time_features.analyize_time_seq import AVG_DISTANCE_FILE, AVG_DIS_FIELD, LABEL_FIELD
from common.draw_picture import draw_scatter
from time_features.analyize_time_seq import DISTANCE_FILE


def read_distance_csv(domain_bad, lag=24):
    csv_file = DISTANCE_FILE + str(domain_bad) + "_" + str(lag) + "_" + AVG_DISTANCE_FILE
    df = pd.read_csv(csv_file)
    # print(len(df))
    x, y = np.array([]), np.array([])
    dn = 34
    for i in range(min(len(df), dn)):
        avg_dis = df.loc[i][AVG_DIS_FIELD]
        label = df.loc[i][LABEL_FIELD]
        x = np.append(x, avg_dis)
        y = np.append(y, label)
    return x, y


if __name__ == '__main__':
    # choice = input("please enter what kind of domains to get: 0 for good doamins, 1 for bad domains")

    # 预期结果： 正常域名之间的相似度大，恶意域名之间的相似度小，因此，正常域名的相似度的均值和方差都较小
    x1, y1 = read_distance_csv(0)
    x3, y3 = read_distance_csv(0, 8)
    # print("x1.size: %s" % (x1.size))

    x2, y2 = read_distance_csv(1)
    x4, y4 = read_distance_csv(1, 8)
    # print("x2.size: %s" % (x2.size))

    print("good domains daily distance mean: %s, std: %s, lag:24" % (x1.mean() * 10000, x1.std() * 10000))
    print("good domains daily distance mean: %s, std: %s, lag:8" % (x3.mean() * 10000, x3.std() * 10000))
    print("bad domains daily distance mean: %s, std: %s, lag:24" % (x2.mean() * 10000, x2.std() * 10000))
    print("bad domains daily distance mean: %s, std: %s, lag:8" % (x4.mean() * 10000, x4.std() * 10000))
    type1 = u"正常域名"
    type2 = u"恶意域名"
    draw_scatter(x1, x3, x2, x4, type1, type2)
    draw_scatter(x1, y1, x2, y2, type1, type2)
    draw_scatter(x3, y3, x4, y2, type1, type2)
