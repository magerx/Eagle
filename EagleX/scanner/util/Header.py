# -*- encoding:utf-8 -*-

"""
File:       Header.py
Author:     magerx@paxmac.org
"""

"""
通用的几个变量，我也不知道为什么是这些数字了，想到一个设一个
有的可以改有的不行，改改还是要斟酌
"""

# 用于输出
DEBUG = True

# 操作KnowledgeBase的一些参数
CRAWL = 0
SQL = 1
JSON = 2
XSS = 14
URL = 3
SRC = 4
STATUS = 13
DOMAIN = 12
LOGIN_FORM = 15
BRUTE = 17
LOG = 18
LFI = 19
CMD = 20
URL_REDIRECT = 21
CODE = 22
INFO = 23

# 数据库的几种操作
INSERT = 5
DELETE = 6
SELECT = 7
CREATE = 8
UPDATE = 9
DROP = 10
INIT = 11

# 这个用到了，但是在逻辑中目前还没有作用
# 用于标识每个进程的身份
# 都是2的幂次是想可以做算术与的操作
CRAWLER = 1
DIR_BURSTER = 2
ROBOTS_KILLER = 4
SRC_DOWNLOADER = 8
SQL_SCANNER = 16
XSS_SCANNER = 32
FORM_AUTH = 64
LFI_SCANNER = 128
CMD_EXEC = 256
URL_REDIRECT = 512
CODE_EXEC = 1024
INFO_Leakage = 2048
