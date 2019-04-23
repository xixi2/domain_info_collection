import numpy as np
import matplotlib.pyplot as plt

plt.rcParams['font.sans-serif'] = ['SimHei']  # 用来正常显示中文标签
plt.rcParams['axes.unicode_minus'] = False  # 用来正常显示负号


def detect_cusum(x, threshold=1, drift=0, ending=False):
    """Cumulative sum algorithm (CUSUM) to detect abrupt changes in data.
    x : 一维数组
    threshold : 变化幅度的阈值
    drift : 消除单词的部分变化：x[i]-x[i-1]-drift
    ending : 是否预测突变点的终点（终点：某种变化趋势改变的地方）
        True(1)：预测变化何时结束；False (0) ：不预测
    show : 布尔值，是否绘图
    ax : a matplotlib.axes.Axes instance, optional (default = None).
    :return
        tai：起点序列
        ta：突变点检测到的时刻序列
        taf：终点序列
        amp：在每一个突变点的起点和终点之间的总变化幅度(终点的值-起点的值)
    """
    x = np.atleast_1d(x).astype('float64')
    gp, gn = np.zeros(x.size), np.zeros(x.size)
    sp, sn = np.zeros(x.size), np.zeros(x.size)
    ta, tai, taf = np.array([[], [], []], dtype=int)
    tap, tan = 0, 0
    amp = np.array([])
    # Find changes (online form)
    for i in range(1, x.size):
        s = x[i] - x[i - 1]  # 差值
        gp[i] = gp[i - 1] + s - drift  # cumulative sum for + change
        gn[i] = gn[i - 1] - s - drift  # cumulative sum for - change

        if gp[i] < 0:
            gp[i], tap = 0, i
        if gn[i] < 0:
            gn[i], tan = 0, i

        # 为了画图
        sp[i], sn[i] = gp[i], gn[i]

        if gp[i] > threshold or gn[i] > threshold:  # change detected!
            # print("change detected! gp[%s]: %s, gn[%s]: %s" % (i, gp[i], i, gn[i]))
            ta = np.append(ta, i)  # alarm index
            start_point = tap if gp[i] > threshold else tan
            tai = np.append(tai, start_point)  # start
            gp[i], gn[i] = 0, 0  # reset alarm
    # THE CLASSICAL CUSUM ALGORITHM ENDS HERE

    # Estimation of when the change ends (offline form)
    if tai.size and ending:
        # 反向查找start
        _, tai2, _, _, _, _ = detect_cusum(x[::-1], threshold, drift)
        taf = x.size - tai2[::-1] - 1

        # Eliminate repeated changes, changes that have the same beginning
        tai, ind = np.unique(tai, return_index=True)
        ta = ta[ind]  # ta为alarm index，ind是
        # taf = np.unique(taf, return_index=False)  # corect later
        if tai.size != taf.size:
            if tai.size < taf.size:
                taf = taf[[np.argmax(taf >= i) for i in ta]]
            else:
                ind = [np.argmax(i >= ta[::-1]) - 1 for i in taf]
                ta = ta[ind]
                tai = tai[ind]
        # Delete intercalated changes (the ending of the change is after
        # the beginning of the next change)
        ind = taf[:-1] - tai[1:] > 0
        if ind.any():
            ta = ta[~np.append(False, ind)]
            tai = tai[~np.append(False, ind)]
            taf = taf[~np.append(ind, False)]
        # Amplitude of changes
        amp = x[taf] - x[tai]
    return ta, tai, taf, amp, sp, sn


def plot_result(x, threshold, drift, ending, ta, tai, taf, gp, gn, file=None):
    _, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 6))

    t = range(x.size)
    ax1.plot(t, x, 'b-', lw=2)
    if len(ta):
        ax1.plot(tai, x[tai], '>', mfc='g', mec='g', ms=10, label=u'起点')

        if ending:
            ax1.plot(taf, x[taf], '<', mfc='g', mec='g', ms=10, label=u'终点')
        ax1.plot(ta, x[ta], 'o', mfc='r', mec='r', mew=1, ms=5, label=u'检测到突变点')
        ax1.legend(loc='best', framealpha=.5, numpoints=1)
    ax1.set_xlim(-.01 * x.size, x.size * 1.01 - 1)
    ax1.set_xlabel(u'时间序列', fontsize=14)
    ax1.set_ylabel(u'序列值', fontsize=14)

    ymin, ymax = x[np.isfinite(x)].min(), x[np.isfinite(x)].max()
    yrange = ymax - ymin if ymax > ymin else 1
    ax1.set_ylim(ymin - 0.1 * yrange, ymax + 0.1 * yrange)
    ax1.set_title(u'时间序列检测到异常点 ' +
                  '(threshold= %.3g, drift= %.3g): 异常点个数 = %d'
                  % (threshold, drift, len(tai)))

    ax2.plot(t, gp, 'y-', label='+')
    ax2.plot(t, gn, 'm-', label='-')
    ax2.set_xlim(-.01 * x.size, x.size * 1.01 - 1)
    ax2.set_xlabel('Data #', fontsize=14)
    ax2.set_ylim(-0.01 * threshold, 1.1 * threshold)
    ax2.axhline(threshold, color='r')
    ax1.set_ylabel(u'原始数据的值', fontsize=14)
    ax2.set_ylabel(u'变化幅度的累积和', fontsize=14)
    ax2.set_title(u'时间序列上升和下降的总幅度的累积和')
    ax2.legend(loc='best', framealpha=.5, numpoints=1)
    plt.tight_layout()
    if file:
        plt.savefig(file)
    else:
        plt.show()
    plt.close()


def test():
    # x = np.array([1,2,3,4,110,25,3,2,1])
    # x = np.array([0, 0, 0, 70, 60, 210, 340, 670, 20, 0, 0, 0, 0])
    x = np.array([0, 0, 5, 20, 50, 70, 20, 210, 340, 670, 20, 0, 0, 0])
    x = np.array([0, -60, -40, -100, -80, -140])
    print("x.shape:", x.shape)
    threshold = 60
    drift = 10
    ending = True
    ta, tai, taf, amp, gp, gn = detect_cusum(x, threshold, drift, ending)
    print("突变点ta: %s" % (ta))
    print("起点tai: %s" % (tai))
    print("结束点taf: %s" % (taf))
    print("振幅amp: %s" % (amp))
    for i, item in enumerate(x):
        print("index: %s, item: %s" % (i, item))
    print(x)
    plot_result(x, threshold, drift, ending, ta, tai, taf, gp, gn, None)
    # plot_result(x, threshold, drift, ending, ta, tai, taf, gp, gn, file)


if __name__ == "__main__":
    test()
