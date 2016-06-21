# -*- encoding:utf-8 -*-

"""
File:       XssScanner.py
Author:     magerx@paxmac.org
"""

import time
import threading

from EagleX.scanner.xss.ReflectedXss import ReflectedXss
from EagleX.scanner.xss.DomXss import DomXss

from EagleX.scanner.util.Header import *

class XssScanner(object):
    """
    XSS扫描器，扫描数据库中的结果并保存到数据库中
    反射型和DOM型两个子模块
    """


    def __init__(self, kb, logger, thread_num_dom, thread_num_reflected, cookie, modules):
        """
        :kb:                    Universal KnowledgeBase
        :logger:                输出
        :thread_num_dom:        dom扫描线程数
        :thread_num_reflected:  反射型线程数
        :cookie:                cookie
        :modules:               启动的模块
        """

        super(XssScanner, self).__init__()

        self.kb = kb
        self.thread_num_dom = thread_num_dom
        self.thread_num_reflected = thread_num_reflected
        self.cookie = cookie
        self.logger = logger

        self.seconds_wait = 2
        self.exit_flag = False

        # 启动对应的模块
        module_list = { 'DOM': self.init_dom,
                        'REFLECTED': self.init_reflected
                        }
        modules_init_func = []
        for active_module in modules:
            if module_list.get(active_module) is not None:
                modules_init_func.append(module_list[active_module])
        self.modules = [init() for init in modules_init_func]

    def init_reflected(self):
        """
        初始化一个反射型对象
        :return:    ReflectedXss对象
        """
        return ReflectedXss(
            kb=self.kb,
            logger=self.logger,
            thread_num=self.thread_num_reflected,
            cookie=self.cookie
            )

    def init_dom(self):
        """
        初始化一个DOM XSS检测对象
        :return:    DomXss对象
        """
        return DomXss(
            kb=self.kb,
            logger=self.logger,
            thread_num=self.thread_num_dom,
            cookie=self.cookie
            )

    def engine_start(self):
        """
        Xss扫描器主函数，启动另外两者
        """
        self.log(['Engine started.'], DEBUG)

        # 启动线程们
        thread_list = [threading.Thread(target=module.engine_start) for module in self.modules]
        for thread in thread_list:
            thread.start()

        # 等待所有线程结束
        for thread in thread_list:
            while True:
                if thread.is_alive():
                    time.sleep(self.seconds_wait)
                    continue
                break

        self.log(['Engine stopped.'], DEBUG)

    def exit(self):
        for module in self.modules:
            module.exit()

    def log(self, msgs, debug):

        if debug:
            self.logger.debug('XssScanner', msgs)
        else:
            self.logger.info('XssScanner', msgs)
