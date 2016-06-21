# -*- encoding:utf-8 -*-

"""
File:       ReflectedXss.py
Author:     magerx@paxmac.org
"""

import time

from EagleX.scanner.util.Header import *
from EagleX.scanner.util.URLUtility import extract_path_query
from EagleX.scanner.util.ParallelDispatcher import ParallelDispatcher
from EagleX.scanner.util.PayloadSender import send_payload

class UrlRedirect(object):
    """
    URL跳转的检测，通过是否跳转到指定页面判断
    """

    def __init__(self, kb, logger, thread_num, cookie):
        """
        :kb:            Universal KnowledgeBase
        :logger:        输出
        :thread_num:    线程数
        :cookie:        cookie
        """
        super(UrlRedirect, self).__init__()

        self.kb = kb
        self.logger = logger
        self.cookie = cookie
        self.owner = 'UrlRedirect'

        self.task_queue = []
        self.seconds_wait = 2
        self.exit_flag = False
        test_urls = [
                    'http://www.baidu.com/',
                    '//baidu.com'
                    ]

        self.payloads = test_urls

        # 线程分发器
        self.dispather = ParallelDispatcher(
            thread_num=thread_num,
            data_source=self.task_queue,
            execute_func=self.check_on_url_redirect,
            logger=self.logger,
            owner=self.owner,
            start_index=0,
            seconds_wait=2
            )

    def engine_start(self):
        """
        URL跳转扫描器主函数，从kb中取数据并进行测试
        """
        self.log(['Engine started.'], DEBUG)
        url_count = 0
        while True:
            # 读取数据，读取完全返回None
            results = self.kb.read_data(URL, URL_REDIRECT, url_count)
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

    def check_on_url_redirect(self, task, thread_no):
        """
        线程执行函数，检测单个URL上的URL跳转漏洞
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
            index = send_payload(url, is_post, query, payload, self.analyze_urlredirect_result, self.cookie)
            if index == -1:
                continue

            # 打印，并保存payload
            self.log(['[VULNERABLE] ' + task[0], '[LOCATION] ' + query[index][0], '[PAYLOAD] ' + payload], not DEBUG)
            self.kb.save_data(URL_REDIRECT, (task[0], query[index][0], payload, 'URL_REDIRECT'))
            break
        else:
            self.log(['[INVULNERABLE] ' + task[0]], DEBUG)

    def analyze_urlredirect_result(self, payload, src, _):
        """
        检测是否跳转到指定页面(百度)
        """
        # print payload
        if u'<title>百度一下，你就知道</title>' in src or u'跳转中' in src:
            return 1
        return 0

    def exit(self):
        self.dispather.exit()
        self.exit_flag = True

    def log(self, msgs, debug):
        if debug:
            self.logger.debug(self.owner, msgs)
        else:
            self.logger.info(self.owner, msgs)
