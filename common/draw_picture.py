# coding:utf-8
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams['font.sans-serif'] = ['SimHei']  # 用来正常显示中文标签
plt.rcParams['axes.unicode_minus'] = False  # 用来正常显示负号


def draw_bar(x_data, y_data, x_min, x_max, title="", xlabel=None, ylabel=None, color="g"):
    """
    :param x_data:
    :param y_data:
    """
    # print("type of x_data: %s" % (type(x_data),))
    plt.bar(x_data, y_data, fc=color, alpha=0.5)
    plt.xlim([x_min, x_max])
    # plt.bar([1,2,3,4],[1,2,3,4],fc='r')
    if xlabel:
        plt.xlabel(xlabel)
    if ylabel:
        plt.ylabel(ylabel)
    plt.title(title)
    if xlabel or ylabel:
        if xlabel:
            plt.xlabel(xlabel)
        if ylabel:
            plt.ylabel(ylabel)
        plt.legend()
    plt.show()
    plt.close()


def draw_pie(label_list, lable_counter, colors=None, explode=None):
    """
    画饼图
    :param ttl_list:
    :param ttl_counter_list:
    :return:
    """
    # labels = 'Frogs', 'Hogs', 'Dogs', 'Logs'
    # sizes = [15, 30, 45, 10]

    # colors = ['yellowgreen', 'gold', 'lightskyblue', 'lightcoral', 'blue']
    # explode = (0, 0.1, 0, 0, 0.05)  # only "explode" the 2nd slice (i.e. 'Hogs')
    # explode = (0, 0, 0, 0, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')

    # plt.pie(sizes, explode=explode, labels=labels, colors=colors,
    #         autopct='%1.1f%%', shadow=True, startangle=90)
    plt.pie(lable_counter, explode=explode, labels=label_list, colors=colors,
            autopct='%1.1f%%', shadow=True, startangle=90)
    # Set aspect ratio to be equal so that pie is drawn as a circle.
    plt.axis('equal')
    plt.show()
    plt.close()


def draw_two_bar(x1, y1, x2, y2, x_min, x_max, label1, label2, xlabel, ylabel, width=1.0, c1='red', c2='blue',
                 title=None):
    # total_width, n = 0.8, 2
    # width = total_width / n
    # x_min, x_max = min(min(x1), min(x2)), max(max(x1), max(x2))
    plt.xlim([x_min, x_max])
    plt.bar(x1, y1, width=width, label=label1, facecolor=c1)
    plt.bar(x2, y2, width=width, label=label2, facecolor=c2)
    if xlabel or ylabel:
        if xlabel:
            plt.xlabel(xlabel)
        if ylabel:
            plt.ylabel(ylabel)
        plt.legend()
    # 注上数值
    # for x, y in zip(x1, y1):
    #     plt.text(x, y, '%.2f' % y, ha='center', va='top')
    plt.show()
    plt.close()


def draw_scatter(x1, y1, x2, y2, type1, type2, xlabel=None, ylabel=None, title1=None, title2=None):
    N = x1.size
    colors = ("red",)
    plt.scatter(x1, y1, c=colors, alpha=0.5, label=type1)
    colors = ("blue",)
    plt.scatter(x2, y2, c=colors, alpha=0.5, label=type2)
    if xlabel:
        plt.xlabel(xlabel)
    if ylabel:
        plt.ylabel(ylabel)
    plt.legend()
    plt.show()
    plt.close()


def draw_line(x1, y1, x2, y2):
    plt.plot(x1, y1, x2, y2)
    # 调用show()函数显示图形
    plt.show()


if __name__ == "__main__":
    size = 5
    # x = np.arange(size)
    # a = np.random.random(size)
    # b = np.random.random(size)
    # print("x: %s, a: %s, b: %s" % (x, a, b))

    x_data = ['2013', '2014', '2015', '2016', '2017', '2018', '2019']
    # 定义2个列表分别作为两条折线的Y轴数据
    y_data = [58000, 60200, 63000, 71000, 84000, 90500, 107000]
    y_data2 = [52000, 54200, 51500, 58300, 56800, 59500, 62700]
    draw_line(x_data, y_data, x_data, y_data2)
