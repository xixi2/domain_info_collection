import numpy as np
from time_features.analyize_time_seq import one_hour2one_period

data = np.array([10, 2, 4, 5, 6, 7, 9, 9, 19, 26])
sum = np.sum(data[:8])
print("sum: ", sum)
data_new = one_hour2one_period(data)
print(data_new)
