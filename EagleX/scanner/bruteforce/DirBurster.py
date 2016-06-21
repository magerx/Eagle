# -*- encoding:utf-8 -*-

"""
File:       DirBurster.py
Author:     magerx@paxmac.org
"""

import requests
import threading
import time

from EagleX.scanner.util.URLUtility import extract_path_domain
from EagleX.scanner.util.ParallelDispatcher import ParallelDispatcher
from EagleX.scanner.util.Header import *

class DirBurster(object):
    """
    目录猜解，独立线程运行
    """

    def __init__(self, kb, thread_num, dic_paths, logger):
        """
        :kb:            Universal KnowledgeBase
        :thread_num:    线程数量
        :dic_paths:     字典路径列表
        :logger:        输出
        """
        super(DirBurster, self).__init__()

        # 禁掉https证书的错误信息
        requests.packages.urllib3.disable_warnings()

        self.kb = kb
        self.logger = logger

        # 读入目录字典
        self.dic = []
        for file_path in dic_paths:
            self.dic.extend(open(file_path, 'r').readlines())
        for i in xrange(0, len(self.dic)):
            self.dic[i] = self.dic[i][1:-1]

        self.exit_flag = False
        self.visited_mutex = threading.Lock()
        self.task_queue = []
        self.visited = {}
        self.seconds_wait = 2

        # 线程分发器
        self.dispather = ParallelDispatcher(
            thread_num=thread_num,
            data_source=self.task_queue,
            execute_func=self.burst_url,
            logger=self.logger,
            owner='DirBurster',
            start_index=0,
            seconds_wait=2
            )

    def engine_start(self):
        """
        从kb中取数据并进行目录猜解
        """
        self.log(['Engine started.'])

        url_count = 0
        while True:
            # 读取数据，读取完全返回None
            results = self.kb.read_data(URL, DIR_BURSTER, url_count)
            if results is None:
                break

            # 读取结果保存到任务列表中，由dispather分发
            if len(results) > 0:
                url_count += len(results)
                self.task_queue.extend([result[0] for result in results])
                self.dispather.dispath_scan_task()

            # 检测到退出标志置位，退出
            if self.exit_flag:
                break
            time.sleep(self.seconds_wait)

        # 等待所有线程结束
        self.dispather.suicide()
        self.log(['Engine stopped.'])

    def burst_url(self, url, thread_no):
        """
        线程执行函数，对url进行目录猜解，保存到数据库
        :url:       目标URL
        :thread_no: 当前线程号
        """
        path, domain = extract_path_domain(url)

        # 猜解目录，得到猜解成功地目录，保存到数据库
        urls = self.parse_path(path, domain)
        self.kb.save_data(URL, [(url, 0, 200, 0) for url in urls])

    def parse_path(self, path, domain):
        """
        递归猜解所有的路径
        :path:      当前路径
        :domain:    当前域名
        :return:    猜解成功的路径列表
        """
        if len(path) == 0:
            return []

        # 如果目录已存在就跳过，否则继续
        full_path = domain + path
        self.visited_mutex.acquire()
        if self.visited.get(full_path) is not None:
            self.visited_mutex.release()
            return []
        self.visited[full_path] = 0
        self.visited_mutex.release()

        # 去掉一层目录，返回检测到的地址
        upper = path[0:-1]
        i = upper.rfind('/')
        if i == -1:
            upper = ''
        else:
            upper = upper[0:i + 1]
        u_list = self.parse_path(upper, domain)
        u_list.extend(self.burst_single(full_path))

        return u_list

    def burst_single(self, url):
        """
        对单个路径进行猜解
        :url:       目标路径
        :return:    猜解成功地目录列表
        """
        u_list = []
        for x in self.dic:
            if self.exit_flag:
                break
            if (self.head_request(url + x)):
                u_list.append(url + x)
        return u_list

    def head_request(self, url):
        """
        发起head请求，目前只是判断了状态码
        """
        try:
            found = requests.head(url, verify=False).status_code == 200
        except:
            found = False
        return found

    def exit(self):
        self.dispather.exit()
        self.exit_flag = True

    def log(self, msgs):
        self.logger.debug('DirBurster', msgs)
