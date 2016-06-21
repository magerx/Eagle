# -*- encoding:utf-8 -*-

"""
File:       INFOLeakage.py
Author:     magerx@paxmac.org
"""

import time
import threading
import re

from EagleX.scanner.info_leakage.dic import *
from EagleX.scanner.util.Header import *
from EagleX.scanner.util.URLUtility import extract_path_query
from EagleX.scanner.util.ParallelDispatcher import ParallelDispatcher
from EagleX.scanner.util.PayloadSender import send_payload

class INFOLeakage(object):
    """
    信息泄露扫描器，扫描数据库中的结果并保存到数据库中
    """

    def __init__(self, kb, logger, thread_num, cookie):
        """
        :kb:                    Universal KnowledgeBase
        :logger:                输出
        :thread_num:            扫描线程数
        :cookie:                cookie
        """
        super(INFOLeakage, self).__init__()

        self.kb = kb
        self.cookie = cookie
        self.logger = logger

        self.task_queue = []
        self.seconds_wait = 2
        self.exit_flag = False
        self.owner = 'INFOLeakage'

        # 线程分发器
        self.dispather = ParallelDispatcher(
            thread_num=thread_num,
            data_source=self.task_queue,
            execute_func=self.check_on_INFO_LEAKAGE,
            logger=self.logger,
            owner=self.owner,
            start_index=0,
            seconds_wait=2
            )


        self.payloads = pathlist

    def engine_start(self):
        """
        主函数，从kb中取数据并进行测试
        """
        self.log(['Engine started.'], DEBUG)

        url_count = 0
        while True:
            # 读取数据，读取完全返回None
            results = self.kb.read_data(URL, INFO_Leakage, url_count)
            if results is None:
                break

            # 添加到任务列表，只取2-POST和1-带参数的GET
            if len(results) > 0:
                url_count += len(results)
                self.task_queue.extend([result for result in results if (result[1] == 1 or result[1] == 2)])
                self.dispather.dispath_scan_task()

            # 检测到退出标志置位，退出
            if self.exit_flag:
                break
            time.sleep(self.seconds_wait)

        # 等待线程关闭
        self.dispather.suicide()
        self.log(['Engine stopped.'], DEBUG)

    def check_on_INFO_LEAKAGE(self, task, thread_no):
        """
        线程执行函数，检测单个URL上的信息泄露
        :task:      (url, is_post, code, depth)的元组
        :thread_no: 当前线程号
        """
        url, query = extract_path_query(task[0])
        is_post = task[1]

        # 对payload中的所有payload挨个检查，一个成功则退出
        for payload in self.payloads.keys():
            # 检测到退出标志置位，退出
            if self.exit_flag:
                self.log(['Thread killed, abort on %s' % task[0]], DEBUG)
                break

            # 发送payload，检查参数位置
            index = send_payload(url, is_post, query, payload, self.analyze_INFO_result, self.cookie)
            if index == -1:
                continue

            # 打印，并保存payload
            self.log(['[VULNERABLE] ' + task[0], '    [LOCATION] ' + query[index][0], '    [PAYLOAD] ' + payload], not DEBUG)
            self.kb.save_data(INFO, (task[0], query[index][0], payload, 'INFO'))
            break
        else:
            self.log(['[INVULNERABLE] ' + task[0]], DEBUG)

    def analyze_INFO_result(self, payload, src, ori_time):
        """
        检查结果中是否有payload，找到对应的返回结果的正则，匹配一下看看
        """
        return self.payloads[payload] in src

    def exit(self):
        self.dispather.exit()
        self.exit_flag = True

    def log(self, msgs, debug):
        if debug:
            self.logger.debug(self.owner, msgs)
        else:
            self.logger.info(self.owner, msgs)
