import os
import pandas as pd

CHOICE_OF_COLLECT_GOOD = 0  # 为正常域名收集信息
CHOICE_OF_COLLECT_BAD = 1  # 为恶意域名收集信息
CHOICE_OF_ANALYIZE_GOOD = 0  # 分析正常域名特征
CHOICE_OF_ANALYIZE_BAD = 1  # 分析恶意域名特征
CHOICE_OF_GOOD = 0
CHOICE_OF_BAD = 1


def remove_file(file):
    if os.path.exists(file):
        os.remove(file)



