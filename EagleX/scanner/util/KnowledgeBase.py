# -*- encoding:utf-8 -*-

"""
File:       KnowledgeBase.py
Author:     magerx@paxmac.org
"""

import sqlite3
import threading
import time
import sys
from EagleX.scanner.util.Header import *
from EagleX.scanner.util.URLUtility import get_domain, get_pattern

reload(sys)
sys.setdefaultencoding('utf8')


class KnowledgeBase(object):
    """
    Universal KnowledgeBase，就是管理爬出来的数据和提供数据
    目前还都是直接存到数据库里，取也是直接取数据库，可以的话多用内存可以修改
    """

    def __init__(self, db_path):
        """
        :db_path:   数据库的路径
        """
        super(KnowledgeBase, self).__init__()

        self.db_path = db_path
        self.srcs = []
        self.login_forms = []
        self.domains = {}
        self.discovered = {}
        self.write_mutex = threading.Lock()
        self.world_end = False

        # 全局用到的SQL语句
        self.sqls = {
            CRAWL: {
                INSERT: 'INSERT INTO URL_ VALUES (%d, \"%s\", %d, %d, %d)',
                DELETE: 'DELETE FROM URL_',
                SELECT: 'SELECT url, is_post, status_code, depth FROM URL_ WHERE id>%d',
                CREATE: 'CREATE TABLE URL_ (id integer primary key, url text, is_post integer, status_code integer, depth integer)',
                DROP: 'DROP TABLE URL_',
                INIT: '',
                UPDATE: 'UPDATE URL_ SET status_code=%d where url=\"%s\"'
            },
            SQL: {
                INSERT: 'INSERT INTO SQL_ VALUES (%d, \"%s\", \"%s\", \"%s\")',
                DELETE: 'DELETE FROM SQL_',
                SELECT: '',
                CREATE: 'CREATE TABLE SQL_ (id integer primary key, url text, dbms text, payload text)',
                DROP: 'DROP TABLE SQL_',
                INIT: '',
                UPDATE: ''
            },
            JSON: {
                INSERT: 'UPDATE JSON_ SET json=\"%s\" WHERE id=0',
                DELETE: 'UPDATE JSON_ SET json="" WHERE id=0',
                SELECT: '',
                CREATE: 'CREATE TABLE JSON_ (id integer primary key, json longtext)',
                DROP: 'DROP TABLE JSON_',
                INIT: 'INSERT INTO JSON_ VALUES (0, "[]")',
                UPDATE: ''
            },
            XSS: {
                INSERT: 'INSERT INTO XSS_ VALUES (%d, \"%s\", \"%s\", \"%s\", \"%s\")',
                DELETE: 'DELETE FROM XSS_',
                SELECT: '',
                CREATE: 'CREATE TABLE XSS_ (id integer primary key, url text, location text, payload text, type text)',
                DROP: 'DROP TABLE XSS_',
                INIT: '',
                UPDATE: ''
            },
            LFI: {
                INSERT: 'INSERT INTO LFI_ VALUES (%d, \"%s\", \"%s\", \"%s\", \"%s\")',
                DELETE: 'DELETE FROM LFI_',
                SELECT: '',
                CREATE: 'CREATE TABLE LFI_ (id integer primary key, url text, location text, payload text, type text)',
                DROP: 'DROP TABLE LFI_',
                INIT: '',
                UPDATE: ''
            },
            CMD: {
                INSERT: 'INSERT INTO CMD_ VALUES (%d, \"%s\", \"%s\", \"%s\", \"%s\")',
                DELETE: 'DELETE FROM CMD_',
                SELECT: '',
                CREATE: 'CREATE TABLE CMD_ (id integer primary key, url text, location text, payload text, type text)',
                DROP: 'DROP TABLE CMD_',
                INIT: '',
                UPDATE: ''
            },
            CODE: {
                INSERT: 'INSERT INTO CODE_ VALUES (%d, \"%s\", \"%s\", \"%s\", \"%s\")',
                DELETE: 'DELETE FROM CODE_',
                SELECT: '',
                CREATE: 'CREATE TABLE CODE_ (id integer primary key, url text, location text, payload text, type text)',
                DROP: 'DROP TABLE CODE_',
                INIT: '',
                UPDATE: ''
            },
            URL_REDIRECT: {
                INSERT: 'INSERT INTO URL_REDIRECT_ VALUES (%d, \"%s\", \"%s\", \"%s\", \"%s\")',
                DELETE: 'DELETE FROM URL_REDIRECT_',
                SELECT: '',
                CREATE: 'CREATE TABLE URL_REDIRECT_ (id integer primary key, url text, location text, payload text, type text)',
                DROP: 'DROP TABLE URL_REDIRECT_',
                INIT: '',
                UPDATE: ''
            },
            INFO: {
                INSERT: 'INSERT INTO INFO_Leakage_ VALUES (%d, \"%s\", \"%s\", \"%s\", \"%s\")',
                DELETE: 'DELETE FROM URL_REDIRECT_',
                SELECT: '',
                CREATE: 'CREATE TABLE INFO_Leakage_ (id integer primary key, url text, location text, payload text, type text)',
                DROP: 'DROP TABLE INFO_Leakage_',
                INIT: '',
                UPDATE: ''
            },
            BRUTE: {
                INSERT: 'INSERT INTO BRUTE_ VALUES (%d, \"%s\", \"%s\", \"%s\", \"%s\")',
                DELETE: 'DELETE FROM BRUTE_',
                SELECT: '',
                CREATE: 'CREATE TABLE BRUTE_ (id integer primary key, url text, para text, payload text, type text)',
                DROP: 'DROP TABLE BRUTE_',
                INIT: '',
                UPDATE: ''
            },
            LOG: {
                INSERT: 'INSERT INTO LOG_ VALUES (%d, \"%s\", \"%s\", \"%s\")',
                DELETE: 'DELETE FROM LOG_',
                SELECT: '',
                CREATE: 'CREATE TABLE LOG_ (id integer primary key, time text, type text, msg text)',
                DROP: 'DROP TABLE LOG_',
                INIT: '',
                UPDATE: ''
            },
        }
        self.count = {_: 0 for _ in self.sqls.keys()}

        # 初始化数据库数据
        self.init_data()

    def clean_up(self):
        """
        其他东西来这里读数据的时候，以None的返回作为退出的标志
        这里就把标记设起来，全局退出来
        当然，还有备份数据库，因为每次用的都是同一个数据库，防止数据没了
        """
        self.world_end = True

        # 备份数据库，以时间命名
        path = self.db_path[0:self.db_path.rfind('/') + 1]
        filename = time.strftime('%y-%m-%d-%H-%M-%S.db', time.localtime(time.time()))
        new_file = path + filename
        open(new_file, 'wb').write(open(self.db_path, 'rb').read())

    def init_data(self):
        """
        初始化数据库，删表，建表，初始化
        """
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        for cmd in self.sqls.keys():
            sqls = self.sqls[cmd]
            try:
                cur.execute(sqls[DROP])
            except:
                pass
            cur.execute(sqls[CREATE])
            cur.execute(sqls[INIT])

        conn.commit()
        cur.close()
        conn.close()

    def read_data(self, cmd, u_id, args):
        """
        读取数据，返回对应的东西
        :cmd:       命令，即要读取什么数据
        :u_id:      读取者的id，目前无用
        :args:      对应的参数，各位不一样
        :return:    None扫描结束，其他情况随具体命令不同
        """
        if self.world_end:
            return None

        # 可用的命令集合
        avalible_cmd = [SRC, URL, DOMAIN, LOGIN_FORM]
        if cmd not in avalible_cmd:
            return 0

        # 读取下载器保存下来的源代码，无参数
        if cmd == SRC:
            # 没有多余的src，返回空串，约定好了
            if len(self.srcs) == 0:
                return ''

            # 返回第一个src，然后删除之
            src = self.srcs[0]
            self.write_mutex.acquire()
            del self.srcs[0]
            self.write_mutex.release()
            return src

        # 读取URL，参数为index，即读取到了第几个URL
        elif cmd == URL:
            # 执行sql，返回读取到的结果，args表示当前cursor
            sql = self.sqls[CRAWL][SELECT] % args
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(sql)
            result = cur.fetchall()
            cur.close()
            conn.close()
            for i in xrange(len(result)):
                if 'logout' in result[i][0]:
                    del result[i]
                    continue
            # 这里又要解个码，其实还是编码到utf-8
            return [(r[0].encode('utf-8'), r[1], r[2], r[3]) for r in result]

        # 读取爬取到的domain，无参数
        elif cmd == DOMAIN:
            # 返回未处理的域名列表，并将返回的域名标记为已处理
            u_list = []
            self.write_mutex.acquire()
            for domain in self.domains.items():
                if domain[1] == 0:
                    u_list.append(domain[0])
                    self.domains[domain[0]] = 1
            self.write_mutex.release()
            return u_list

        # 读取爬取到的登录表单，(none, none)为没有数据
        elif cmd == LOGIN_FORM:
            if len(self.login_forms) == 0:
                return None, None

            # 返回第一个form，然后删除之
            form = self.login_forms[0]
            self.write_mutex.acquire()
            del self.login_forms[0]
            self.write_mutex.release()
            return form

    def save_data(self, cmd, args):
        """
        保存数据，根据不同的命令，args的内容会不一致
        :cmd:       具体的命令
        :args:      参数
        :return:    大部分时候并不需要返回结果，只有插入URL的时候，返回一下去重之后的URL
        """
        # 可用的命令列表
        avalible_cmd = [SRC, URL, SQL, JSON, STATUS, XSS, LOGIN_FORM, BRUTE, LOG, LFI, CMD, CODE, URL_REDIRECT, INFO]
        if cmd not in avalible_cmd:
            return None

        # 对数据库的访问全部锁住
        self.write_mutex.acquire()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        # 保存源码，参数格式(url, src, depth)
        if cmd == SRC:
            self.srcs.append(args)

        # 保存URL列表，参数格式[(url, is_post, code, depth), ]
        elif cmd == URL:
            # 去重，保存domain
            args = self._encode_filter(args)
            self.save_domain(args)

            for x in args:
                # 2-post，1-get with para, 0-nothing
                is_query = 2 if x[1] == 1 else (1 if x[0].find('?') != -1 else 0)
                self.count[CRAWL] += 1
                sql = self.sqls[CRAWL][INSERT] % (self.count[CRAWL], x[0].replace('"', '""'), is_query, x[2], x[3])
                cur.execute(sql)

        # 保存SQL注入的payload信息，参数格式(url, dbms, payload)
        elif cmd == SQL:
            self.count[SQL] += 1
            sql = self.sqls[SQL][INSERT] % (
                self.count[SQL], args[0].replace('"', '""'), args[1].replace('"', '""'), args[2].replace('"', '""'))
            cur.execute(sql)

        # 保存JSON到数据库中，参数格式str
        elif cmd == JSON:
            sql = self.sqls[JSON][INSERT] % args.replace('"', '""')
            cur.execute(sql)

        # 更新URL的状态码，参数格式为(url, code)
        elif cmd == STATUS:
            sql = self.sqls[CRAWL][UPDATE] % (args[1], args[0].replace('"', '""'))
            cur.execute(sql)

        # 保存XSS注入的payload信息，参数格式为(url, location, payload, type)
        # 或者是BRUTE的结果，格式差不多，参数格式为(url, para, payload, type)
        # 还有LFI的结果，格式与xss保持一致
        elif cmd in [XSS, BRUTE, CMD, CODE, LFI, URL_REDIRECT, INFO]:
            self.count[cmd] += 1
            sql = self.sqls[cmd][INSERT] % (
                self.count[cmd], args[0].replace('"', '""'), args[1].replace('"', '""'), args[2].replace('"', '""'),
                args[3].replace('"', '""'))
            cur.execute(sql)

        # 保存找到的登录表单
        elif cmd == LOGIN_FORM:
            self.login_forms.extend(args)

        # 保存日志
        elif cmd == LOG:
            self.count[cmd] += 1
            sql = self.sqls[cmd][INSERT] % (
                self.count[cmd], args[0].replace('"', '""'), args[1].replace('"', '""'), args[2].replace('"', '""'))
            cur.execute(sql)

        conn.commit()
        cur.close()
        conn.close()
        self.write_mutex.release()

        # 只有保存数据库的时候，args变成了过滤后的东西
        # 其他保存都是原样返回，并卵
        return args

    # TODO: 考虑重新，用布隆过滤器+hash的形式
    def _encode_filter(self, items):
        """
        对URL进行去重，并且进行URL编码
        :items:     格式[(url, is_post, code, depth), ]
        :return:    格式一致，去重后的结果
        """
        # 对URL进行get_pattern的操作，模式化，然后保存在字典里
        results = []
        for item in items:
            try:
                _encoded = item[0].encode('utf-8')
            except Exception as e:
                _encoded = item[0]
            pattern = get_pattern(_encoded)
            if self.discovered.get(pattern) is None:
                results.append((_encoded, item[1], item[2], item[3]))
                self.discovered[pattern] = 0
        return results

    def save_domain(self, results):
        """
        对新的URL提取domain，保存
        :results:       url列表，格式[(url, is_post, status_code, depth), ]
        """
        for result in results:
            domain = get_domain(result[0])
            if self.domains.get(domain) is None:
                self.domains[domain] = 0
