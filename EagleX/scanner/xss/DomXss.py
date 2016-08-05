# -*- encoding:utf-8 -*-

"""
File:       DomXss.py
Author:     magerx@paxmac.org
"""

import time

from EagleX.scanner.xss.XssPayloads import JS_FUNCTION_CALLS
from EagleX.scanner.xss.XssPayloads import DOM_USER_CONTROLLED
from EagleX.scanner.xss.XssPayloads import _script_src_re

from EagleX.scanner.util.Header import *
from EagleX.scanner.util.ParallelDispatcher import ParallelDispatcher
from EagleX.scanner.util.PayloadSender import send_common_request
from EagleX.scanner.util.URLUtility import url_process


class DomXss(object):
    """
    检测DOM XSS，检查页面中可控字段，无需发送payload
    """

    def __init__(self, kb, logger, thread_num, cookie):
        """
        :kb:            Universal KnowledgeBase
        :logger:        输出
        :thread_num:    线程数
        :cookie:        cookie
        """
        super(DomXss, self).__init__()

        self.kb = kb
        self.logger = logger
        self.cookie = cookie
        self.owner = 'DomXss'

        self.task_queue = []
        self.visited = {}
        self.seconds_wait = 2
        self.exit_flag = False

        # 线程分发器
        self.dispather = ParallelDispatcher(
            thread_num=thread_num,
            data_source=self.task_queue,
            execute_func=self.check_on_dom_xss,
            logger=self.logger,
            owner=self.owner,
            start_index=0,
            seconds_wait=2
        )

    def engine_start(self):
        """
        检测DOM XSS主函数
        """
        url_count = 0
        while True:
            # 读取数据，读取完全返回None
            results = self.kb.read_data(URL, XSS_SCANNER, url_count)
            if results is None:
                break

            # 所有的URL都添加到任务列表
            if len(results) > 0:
                url_count += len(results)
                self.task_queue.extend(results)
                self.dispather.dispath_scan_task()

            # 检测到退出标志置位，退出
            if self.exit_flag:
                break
            time.sleep(self.seconds_wait)

        # 等待线程关闭
        self.dispather.suicide()

    def check_on_dom_xss(self, task, thread_no):
        """
        线程执行函数，检查可能的DOM输出点，包括其他包含的JS
        :task:      (url, is_post, code, depth)的元组
        :thread_no: 当前线程号
        """
        # 下载原页面，找到所有js src，访问并保存
        src = {task[0]: send_common_request(task[0], task[1], self.cookie)}
        for js in _script_src_re.findall(src[task[0]]):
            # 检测到退出标志置位，退出
            if self.exit_flag:
                self.log(['Thread killed, abort on %s' % task[0]], DEBUG)
                return

            # 访问js并且保存代码，重复不再爬取
            # 这里有个问题是，如果是某个js中有输出点，那第一个被检查出来之后后面的就不管了
            # 理论上不太可能是某个js中，就算是，至少也会爆出来一个。还算可以接受
            link = url_process(js, task[0])
            if self.visited.get(link) is not None:
                continue
            self.visited[link] = 0
            src[js] = send_common_request(link, 0, '')

        # 检查所有的src中的输出点，存在则保存
        for url in src.keys():
            res = self.analyze_dom_result(src[url])
            if res is not None:
                # 打印，并保存payload
                self.log(['[VULNERABLE] ' + task[0], '[FILE] ' + url, '[KEYWORD] ' + res], not DEBUG)
                self.kb.save_data(XSS, (task[0], url, res, 'DOM'))
                break
        else:
            self.log(['[INVULNERABLE] ' + task[0]], DEBUG)

    def analyze_dom_result(self, response):
        """
        检查源代码中是否有DOM的输出点
        :response:      源代码
        :return:        不存在则None，否则可控点的字符串
        """
        res = ''
        for function_re in JS_FUNCTION_CALLS:
            parameters = function_re.search(response)
            if parameters:
                for user_controlled in DOM_USER_CONTROLLED:
                    if user_controlled in parameters.groups()[0]:
                        res = '|'.join([res, user_controlled])
        if len(res) > 0:
            return res[1:]
        else:
            return None

    def exit(self):
        self.dispather.exit()
        self.exit_flag = True

    def log(self, msgs, debug):
        if debug:
            self.logger.debug(self.owner, msgs)
        else:
            self.logger.info(self.owner, msgs)
