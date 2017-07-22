# -*- coding:utf8
# using: python3
import numpy as np
import pandas as pd
import xgboost as xgb
import matplotlib.pyplot as plt

####################################
# Data Path
####################################

file_path1 = '/Volumes/Transcend/HackNtu_2017/Security/Raw Data/train.csv'
file_path2 = '/Volumes/Transcend/HackNtu_2017/Security/Raw Data/val.csv'

####################################
# Reading Dating
####################################
df_train = pd.read_csv(file_path1)
df_val = pd.read_csv(file_path2)
df_train.drop('device_hashed_mac', axis= 1,inplace = True)
df_val.drop('device_hashed_mac', axis= 1,inplace = True)
df_val = df_train.loc[df_train['event_flow_outbound_or_inbound'] == 'outbound' ]# For 判斷此為被攻擊的數據
df_val = df_val.loc[df_val['event_flow_outbound_or_inbound'] == 'outbound' ]
df_train.head()

####################################
# Data Preparation
####################################
def groundtruth_for_xgb(groundtruth):
    # The function is for class is represented by a number and should be from 0 to num_class - 1. 
    output = groundtruth.tolist()
    min_ = min(output)
    output = np.array([ i- min_ for i in output])
    return output
X_train = df_train.values[:,[i+2 for i in range(6)] +[-2]]
X_val = df_val.values[:,[i+2 for i in range(6)] +[-2]]
target_index = df_train.columns.tolist().index('event_rule_severity')
y_train = groundtruth_for_xgb(df_train.values[:,target_index])
y_val = groundtruth_for_xgb(df_val.values[:,target_index])


df_columns = ["device_dev_name", "device_family_name", "device_os_name", "device_type_name", "device_vendor_name", "event_protocol_id",'event_time']

X_train = X_train.astype(float) 
X_val = X_val.astype(float)

print('X_train shape is', X_train.shape)
print('y_train shape is', y_train.shape)
print('X_val shape is', X_val.shape)
print('y_val shape is', y_val.shape)

####################################
#xgb format of data set 
####################################
dtrain = xgb.DMatrix(X_train, y_train, feature_names=df_columns)
dval = xgb.DMatrix(X_val, y_val, feature_names=df_columns)
####################################
# training 
####################################
xgb_params = {
    'booster':'gbtree',
    'eta': 0.3,
    'max_depth': 15,
    'subsample': 1.0,
    'colsample_bytree': 0.7,
    'objective': 'multi:softmax',
    'num_class': 3 ,
    'eval_metric': 'merror',
    'silent': 1
}

'''
parameter
eta:
step size shrinkage used in update to prevents overfitting.
After each boosting step, we can directly get the weights of new features. 
and eta actually shrinks the feature weights to make the boosting process more conservative.
like regularization
'''

'''
Before running XGboost, 
we must set three types of parameters: 
1.general parameters # it relates to which booster we are using to do boosting, commonly tree or linear model
2.booster parameters 
3.task parameters. # it depends on taskt such as ranking task, regression task

'''
model = xgb.train(xgb_params, dtrain, num_boost_round=500, evals=[(dval, 'val')],
                       early_stopping_rounds=20, verbose_eval = 20)

num_boost_round = model.best_iteration 

####################################
# Feature Importance
####################################

fig, ax = plt.subplots(1, 1, figsize=(8, 16))
xgb.plot_importance(model, height=0.5, ax=ax,)
plt.show()

####################################
# Saving the model
####################################
model = xgb.train(dict(xgb_params, silent=0), dtrain, num_boost_round = num_boost_round)# Booster object
model.save_model('event_rule_severity.model')

####################################
# Loading the model
####################################
load_path = '/Volumes/Transcend/HackNtu_2017/Security/Model/event_rule_severity.model'
model = xgb.Booster({'nthread':4}) #init model
model.load_model(load_path) # load data
####################################
# prediction
####################################
y_pred = model.predict(dval)
print (y_pred)