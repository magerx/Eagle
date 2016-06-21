# -*- encoding:utf-8 -*-

"""
File:       SqlScanner.py
Author:     magerx@paxmac.org
"""

import threading
import time
import subprocess
import os

from EagleX.scanner.sql.AutoSqli import AutoSqli
from EagleX.scanner.util.ParallelDispatcher import ParallelDispatcher
from EagleX.scanner.util.Header import *

class SqlScanner(object):
    """
    SQL注入扫描的主引擎
    """

    def __init__(self, kb, sqlmapapi_path, sqlmapapi_port, logger, cookie, sqlmapapi_addr, thread_num, temp_dir_path):
        """
        :kb:                Universal KnowledgeBase
        :sqlmapapi_path:    脚本的路径
        :sqlmapapi_port:    监听的端口
        :sqlmapapi_addr:    监听的地址，默认localhost
        :logger:            输出
        :cookie:            cookie，默认为空
        :thread_num:    最大的线程数
        :temp_dir_path:     临时文件夹
        """
        super(SqlScanner, self).__init__()

        self.kb = kb
        self.logger = logger
        self.cookie = cookie
        self.temp_dir_path = temp_dir_path

        self.task_queue = []
        self.seconds_wait = 2      # 检测新加进来的URL
        self.sqlmapapi_process = None
        self.exit_flag = False
        self.sqlmapapi_server = ''.join(['http://', sqlmapapi_addr, ':' , str(sqlmapapi_port)])

        # autosqli的对象列表
        self.autosqli_list = [None for i in xrange(thread_num)]
        self.autosqli_list_mutex = threading.Lock()

        # 线程分发器
        self.dispather = ParallelDispatcher(
            thread_num=thread_num,
            data_source=self.task_queue,
            execute_func=self.check_on_sql_injection,
            logger=self.logger,
            owner='SqlScanner',
            start_index=0,
            seconds_wait=1
            )

        # 开启sqlmapapi服务
        self.start_sqlmapapi_server(sqlmapapi_path, sqlmapapi_addr, sqlmapapi_port)

    def start_sqlmapapi_server(self, path, addr, port):
        """
        开启sqlmapapi服务，输出重定向到文件中
        :path:      可执行路径
        :addr:      服务器监听地址
        :port:      服务器监听端口
        """
        self.f_out = open(self.temp_dir_path + 'sqlmapapi.stdout.temp', 'w')
        self.f_err = open(self.temp_dir_path + 'sqlmapapi.stderr.temp', 'w')

        # 更改脚本当前路径，防止sqlmapapi后续调用路径错误
        # 不再修改路径，把sqlmap放到了根目录下面，然后修改了api.py

        self.sqlmapapi_process = subprocess.Popen(
            ['python', path, '-s', '-H', addr, '-p', str(port)],
            shell=False,
            stdout=self.f_out,
            stderr=self.f_err
            )

        self.log(['sqlmapapi server started at %s:%d.' % (addr, port)], DEBUG)

    def engine_start(self):
        """
        Sql扫描器主函数，从kb中取数据并进行测试
        """
        self.log(['Engine started.'], DEBUG)

        url_count = 0
        while True:
            # 读取URL数据，读取完全返回None
            results = self.kb.read_data(URL, SQL_SCANNER, url_count)
            if results is None:
                break

            # 添加到任务列表，只取2-POST和1-带参数的GET
            if len(results) > 0:
                url_count += len(results)
                self.task_queue.extend([result for result in results if (result[1] >= 1)])# or result[1] == 2)])
                self.dispather.dispath_scan_task()

            # 检测到退出标志置位，退出
            if self.exit_flag:
                break
            time.sleep(self.seconds_wait)

        # 清理现场，退出
        self.clean_up_the_mess()
        self.log(['Engine stopped.'], DEBUG)

    def check_on_sql_injection(self, task, thread_no):
        """
        线程执行函数，检查单个URL的注入，结果保存到数据库
        :task:      (url, is_post, code, depth)的元组
        :thread_no: 当前线程号，用于保存sqli
        """
        url = task[0]
        para = ''

        # POST则分隔开参数
        if task[1] == 2:
            url, para = url.split('?', 1)

        # 启动mAutoSqli调用sqlmapapi进行检测，添加到对象列表中
        sqli = AutoSqli(
            server=self.sqlmapapi_server,
            target=url,
            logger=self.logger,
            timeout=120,
            data=para,
            referer='',
            cookie=self.cookie,
            other_options={},
            retries=3)
        self.autosqli_list_mutex.acquire()
        self.autosqli_list[thread_no] = sqli
        self.autosqli_list_mutex.release()

        # 测完了要组装回去
        url += '?' + para if len(para) > 0 else ''

        # 扫描结果处理
        result = sqli.scan()
        if result is None:
            self.log(['[INVULNERABLE] ' + url], DEBUG)
        elif len(result) > 0:
            # 输出dbms和payload信息，保存到数据库
            (dbms, payload) = self.get_info(result)
            self.log(['[VULNERABLE] ' + url, '[DBMS] ' + dbms, '[PAYLOAD] ' + payload], not DEBUG)
            self.kb.save_data(SQL, (url, dbms, payload))

    def get_info(self, result):
        """
        从Json格式的数据中读取到dbms和payload
        :result:    JSON数据
        :return:    (dbms, payload)
        """
        payload = ''
        dbms = ''
        try:
            data = result[0]['value'][0]['data']
            dbms = result[0]['value'][0]['dbms']
            if dbms is None:
                dbms = ''
            if data is None:
                raise NameError('')

            # 多个payload，用\n连接成串
            data_list = list(data)
            for x in data_list:
                try:
                    payload += '' if data[x]['payload'] == None else (data[x]['payload'] + '\n')
                except:
                    pass
            if (len(payload) > 0):
                payload = payload[0:-1] # 删除最后的回车
        except:
            pass
        return (dbms, payload)

    def clean_up_the_mess(self):
        """
        杀死AutoSqli对象，停止线程
        """
        # 杀死测试线程
        self.autosqli_list_mutex.acquire()
        for x in self.autosqli_list:
            if x != None:
                x.exit()
        self.autosqli_list_mutex.release()

        # 等待线程结束
        self.dispather.suicide()

        # 杀死sqlmapapi
        if self.sqlmapapi_process:
            try:
                self.sqlmapapi_process.kill()
                self.log(['sqlmapapi server stopped.'], DEBUG)
                self.f_out.close()
                self.f_err.close()
            except:
                pass

    def exit(self):
        self.dispather.exit()
        self.exit_flag = True

    def log(self, msgs, debug):
        if debug:
            self.logger.debug('SqlScanner', msgs)
        else:
            self.logger.info('SqlScanner', msgs)
