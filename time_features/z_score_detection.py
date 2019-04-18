import numpy as np
from matplotlib.pylab import plt

AVG_FILTER = "avg_filter"
STD_FILTER = "std_filter"
Z_SCORE_SIGNALS = "signals"


def thresholding_algo(y, lag, threshold, influence):
    """
    :param y:
    :param lag: 滑动窗口的长度
    :param threshold: 阈值， 如阈值为3表示，当数据点和均值之间相差3个标准差时，该数据点为异常点
    :param influence: 平滑因子：在0-1之间；异常点对未来的阈值的影响，为0时表示异常点为未来的阈值无影响
    :return:
    """
    signals = np.zeros(len(y))
    filtered_y = np.array(y)
    avg_filter = [0] * len(y)
    std_filter = [0] * len(y)
    avg_filter[lag - 1] = np.mean(y[0:lag])
    std_filter[lag - 1] = np.std(y[0:lag])
    for i in range(lag, len(y)):
        # 发现异常点：异常点定义为在当前均值的5sigma范围外的点
        if abs(y[i] - avg_filter[i - 1]) > threshold * std_filter[i - 1]:
            if y[i] > avg_filter[i - 1]:
                signals[i] = 1
            else:
                signals[i] = -1
            filtered_y[i] = influence * y[i] + (1 - influence) * filtered_y[i - 1]
            avg_filter[i] = np.mean(filtered_y[(i - lag):i])
            std_filter[i] = np.std(filtered_y[(i - lag):i])
        else:
            signals[i] = 0
            filtered_y[i] = y[i]
            avg_filter[i] = np.mean(filtered_y[(i - lag):i])
            std_filter[i] = np.std(filtered_y[(i - lag):i])
    print("np.asarray(std_filter): %s" % (np.asarray(std_filter),))
    return dict(signals=np.asarray(signals), avg_filter=np.asarray(avg_filter),
                std_filter=np.asarray(std_filter))


def plot_result(y, result, threshold, title):
    """
    :param title:
    :return:
    蓝色为原始数据， 亮绿色为均值, 绿色为正常范围上界，蓝色为正常范围下界
    """
    avg = result[AVG_FILTER]
    std = result[STD_FILTER]
    upper_bound = avg + threshold * std
    lower_bound = avg - threshold * std
    print("upper_bound: %s, lower_bound: %s" % (upper_bound, lower_bound))
    signals = result[Z_SCORE_SIGNALS]
    data_points_number = np.arange(1, len(y) + 1)
    plt.subplot(211)
    plt.plot(data_points_number, y)
    plt.plot(data_points_number, avg, color="cyan", lw=2)
    plt.plot(data_points_number, upper_bound, color="green", lw=2)
    plt.plot(data_points_number, lower_bound, color="blue", lw=2)
    plt.subplot(212)
    plt.step(data_points_number, signals, color="red", lw=2)
    plt.ylim(-1.5, 1.5)
    plt.savefig(title)
    plt.show()


def z_score_peak_detect(y, title):
    """
    此函数中设置lag，threshold，influence等参数并调用thresholding_algo函数并绘制图像
    :param y:
    :return:
    """
    lag = 8
    threshold = 3
    influence = 0
    result = thresholding_algo(y, lag=lag, threshold=threshold, influence=influence)
    plot_result(y, result, threshold, title)
    signals = result[Z_SCORE_SIGNALS]
    return signals


if __name__ == "__main__":
    y = np.array([
        1, 1, 1.1, 1, 0.9, 1, 1, 1.1, 1, 0.9, 1, 1.1, 1, 1, 0.9, 1, 1, 1.1, 1, 1,
        1, 1, 1.1, 0.9, 1, 1.1, 1, 1, 0.9, 1, 1.1, 1, 1, 1.1, 1, 0.8, 0.9, 1, 1.2,
        0.9, 1, 1, 1.1, 1.2, 1, 1.5, 1, 3, 2, 5, 3, 2, 1, 1, 1, 0.9, 1, 1, 3,
        2.6, 4, 3, 3.2, 2, 1, 1, 0.8, 4, 4, 2, 2.5, 1, 1, 1]
    )
    title = "1.png"
    z_score_peak_detect(y, title)
