# -*- encoding:utf-8 -*-

"""
File:       ReflectedXss.py
Author:     magerx@paxmac.org
"""

import time

from EagleX.scanner.xss.XssPayloads import replace_randomize
from EagleX.scanner.xss.XssPayloads import PAYLOADS

from EagleX.scanner.util.Header import *
from EagleX.scanner.util.URLUtility import extract_path_query
from EagleX.scanner.util.ParallelDispatcher import ParallelDispatcher
from EagleX.scanner.util.PayloadSender import send_payload

class ReflectedXss(object):
    """
    反射型或者存储型XSS的检测，payload直接echo在返回的页面中
    """

    def __init__(self, kb, logger, thread_num, cookie):
        """
        :kb:            Universal KnowledgeBase
        :logger:        输出
        :thread_num:    线程数
        :cookie:        cookie
        """
        super(ReflectedXss, self).__init__()

        self.kb = kb
        self.logger = logger
        self.cookie = cookie
        self.owner = 'ReflectedXss'

        self.task_queue = []
        self.seconds_wait = 2
        self.exit_flag = False

        # 替换后的payload们
        self.payloads = [replace_randomize(i) for i in PAYLOADS]

        # 线程分发器
        self.dispather = ParallelDispatcher(
            thread_num=thread_num,
            data_source=self.task_queue,
            execute_func=self.check_on_reflected_xss,
            logger=self.logger,
            owner=self.owner,
            start_index=0,
            seconds_wait=2
            )

    def engine_start(self):
        """
        反射型Xss扫描器主函数，从kb中取数据并进行测试
        """
        url_count = 0
        while True:
            # 读取数据，读取完全返回None
            results = self.kb.read_data(URL, XSS_SCANNER, url_count)
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

    def check_on_reflected_xss(self, task, thread_no):
        """
        线程执行函数，检测单个URL上的XSS漏洞
        :task:      (url, is_post, code, depth)的元组
        :thread_no: 当前线程号
        """
        url, query = extract_path_query(task[0])
        is_post = task[1]

        # 对payload中的所有payload挨个检查，一个成功则退出
        for payload in self.payloads:
            # 检测到退出标志置位，退出
            if self.exit_flag:
                self.log(['Thread killed, abort on %s' % task[0]], DEBUG)
                break

            # 发送payload，检查参数位置
            index = send_payload(url, is_post, query, payload, self.analyze_reflected_result, self.cookie)
            if index == -1:
                continue

            # 打印，并保存payload
            self.log(['[VULNERABLE] ' + task[0], '[LOCATION] ' + query[index][0], '[PAYLOAD] ' + payload], not DEBUG)
            self.kb.save_data(XSS, (task[0], query[index][0], payload, 'XSS'))
            break
        else:
            self.log(['[INVULNERABLE] ' + task[0]], DEBUG)

    def analyze_reflected_result(self, payload, src, _):
        """
        检查结果中是否有payload，现在是检查payload原文是否在返回来的源代码中
        """
        return payload in src

    def exit(self):
        self.dispather.exit()
        self.exit_flag = True

    def log(self, msgs, debug):
        if debug:
            self.logger.debug(self.owner, msgs)
        else:
            self.logger.info(self.owner, msgs)
