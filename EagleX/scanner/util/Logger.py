# -*- encoding:utf-8 -*-

"""
File:       Logger.py
Author:     magerx@paxmac.org
"""

import threading
import time
from EagleX.scanner.util.Header import *


class Logger(object):
    """
    全局的输出类
    """

    def __init__(self, redirect, debug, kb):
        """
        :redirect:  输出重定向，默认stdout
        :debug:     debug信息输出控制
        :kb:        Universal KnowledgeBase，保存日志用
        """
        super(Logger, self).__init__()
        self.redirect = redirect
        self._debug = debug
        self.kb = kb
        self.mutex = threading.Lock()

    def info(self, owner, msgs):
        """
        输出info信息
        :owner: 消息所属的模块
        :msgs:  字符串列表
        """
        self._do_log(owner, msgs, False)

    def debug(self, owner, msgs):
        """
        输出debug信息，需要取决于是否输出debug
        :owner: 消息所属的模块
        :msgs:  字符串列表
        """
        if self._debug:
            self._do_log(owner, msgs, True)

    def _do_log(self, owner, msgs, debug):
        """
        需要获得输出线程锁，保存日志
        :owner: 消息所属的模块
        :msgs:  字符串列表
        :debug: debug或者info
        """
        extra = '[DEBUG]' if debug else '[INFO]'
        extra = '%s [%s]' % (extra, owner)

        self.mutex.acquire()

        format_time = time.strftime('[%H:%M:%S]', time.localtime(time.time()))
        header = "%s %s" % (format_time, extra)
        for msg in msgs:
            self.kb.save_data(LOG, (format_time, extra, msg))
            if '[VULNERABLE]' in msgs[0]:
                self.redirect.write("\033[0;32;40m%s %s \033[0m \n" % (header, msg))
            else:
                self.redirect.write("%s %s\n" % (header, msg))

        self.mutex.release()
