#-*- coding:utf8
# using python3 
import sys
import numpy as np
import pandas as pd
import json
import time
import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn import preprocessing

######################################
# Data Path
###################################### 
file_path1 = '/Volumes/Transcend/HackNtu_2017/Security/Raw Data/train.csv'
file_path2 = '/Volumes/Transcend/HackNtu_2017/Security/Raw Data/val.csv'

####################################
# Reading Dating
####################################
df_train = pd.read_csv(file_path1)
df_val = pd.read_csv(file_path2)

######################################
# Preparing X_train and y_train
###################################### 

df_train.drop('device_hashed_mac', axis= 1,inplace = True)
df_val.drop('device_hashed_mac', axis= 1,inplace = True)
df_val = df_train.loc[df_train['event_flow_outbound_or_inbound'] == 'outbound' ]# For 判斷此為被攻擊的數據
df_val = df_val.loc[df_val['event_flow_outbound_or_inbound'] == 'outbound' ]
df_train.head()
def groundtruth_for_xgb(groundtruth):
    # The function is for class is represented by a number and should be from 0 to num_class - 1. 
    output = groundtruth.tolist()
    min_ = min(output)
    output = np.array([ i- min_ for i in output])
    return output
    
X_train = df_train.values[:,[i+2 for i in range(6)] +[-2]]
X_val = df_val.values[:,[i+2 for i in range(6)] +[-2]]
target_index = df_train.columns.tolist().index('event_rule_category')
y_train = groundtruth_for_xgb(df_train.values[:,target_index])
y_val = groundtruth_for_xgb(df_val.values[:,target_index])


df_columns = ["device_dev_name", "device_family_name", "device_os_name", "device_type_name", "device_vendor_name", "event_protocol_id",'event_time']

X_train = X_train.astype(float) 
X_val = X_val.astype(float)

print('X_train shape is', X_train.shape)
print('y_train shape is', y_train.shape)
print('X_val shape is', X_val.shape)
print('y_val shape is', y_val.shape)
######################################
# preference_inferring : Logistic Regression
#######################################
print ('Random RandomForest')
clf = RandomForestClassifier(n_estimators = 20)

#######################################
# Training 
#######################################
s = time.time()
clf.fit(X_train, y_train)

print ('Accuracy of training set',clf.score(X_train,y_train)) #  90.5410237108 %
print ('Training Finished!!!!!')
e = time.time()

print ('Training time :' + str(e-s) + ' secs') # Training time :5924.4448499679565 secs=~ 1.64 hrs 

#######################################
# Validating 
#######################################

print ('Accuracy of Validating set',clf.score(X_val,y_val))


