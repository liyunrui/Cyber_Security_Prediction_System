# -*- coding:utf8
# using python3
import numpy as np
import pandas as pd
import json
####################################
# Data Path
####################################
file_path = '/Volumes/Transcend/HackNtu_2017/Security/Raw Data/TBrain_IPS_new.csv' # It comes from another code

####################################
# Reading Dating
####################################
Data = pd.read_csv(file_path)
columns = Data.columns


####################################
# Splitting Data into training set and testing set
####################################
def data_splitting(value_of_target):
	frames_train = []
	frames_val = []
	# input : value of target : list-like
	# output: frames waiting to cancatenate 
	for value in value_of_target:
		## DataFrame.drapna(): return a dataframe without any missing values
		base = Data.loc[Data['event_rule_severity'] == value].dropna()
		## sampling 80 percent of data as training set
		df1_train = base.sample(frac=0.8)
		df1_val = base.drop(df1_train.index[[i for i in range(df1_train.shape[0])]])

		frames_train.append(df1_train)
		frames_val.append(df1_val)

	return pd.concat(frames_train), pd.concat(frames_val) # Dtrain, Dval

Dtrain, Dval = data_splitting([3,4,5])	

def convert_str_to_nominal_variables(data2, col_name):
    # input: col_name(str)
    data_tmp = data2[col_name]
    cat = list(enumerate(list(data_tmp.unique())))
    table = dict()
    for item in cat:
        table[item[1]] = item[0]
    with open('%s.json'%(col_name), 'w') as fp:
    	json.dump(table, fp)
    data2 = data2.replace({col_name: table })
    return data2

df_columns = ["device_dev_name", "device_family_name", "device_os_name", "device_type_name", "device_vendor_name",'event_rule_category']

t = 0
for name in df_columns:
	t += 1
	Dtrain = convert_str_to_nominal_variables(Dtrain, name)
	Dval = convert_str_to_nominal_variables(Dval, name)
	print ('目前進度', 1.0 * t / len(df_columns))

####################################
# Saving 
####################################
saving_path1 = '/Volumes/Transcend/HackNtu_2017/Security/Raw Data/train.csv'
saving_path2 = '/Volumes/Transcend/HackNtu_2017/Security/Raw Data/val.csv'
Dtrain.to_csv(saving_path1)
Dval.to_csv(saving_path2)

print ('Finished !!!!')
