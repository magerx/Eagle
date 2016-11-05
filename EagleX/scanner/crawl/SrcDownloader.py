# -*- encoding:utf-8 -*-

"""
File:       SrcDownloader.py
Author:     magerx@paxmac.org
"""

import subprocess
import time
import re
import os
from urlparse import urlparse

from EagleX.scanner.util.ParallelDispatcher import ParallelDispatcher
from EagleX.scanner.util.Header import *


class SrcDownloader(object):
    """
    下载器模块，下载源代码，并且保存到kb
    """

    def __init__(self, kb, phantomjs_path, evaljs_path, logger, thread_num, filetype_whitelist, depth_limit,
                 temp_dir_path):
        """
        :kb:                Universal KnowledgeBase
        :phantomjs_path:    phantomjs路径
        :evaljs_path:       js脚本路径
        :logger:            输出
        :thread_num:        最大线程数
        :filetype_whitelist:文件类型白名单
        :depth_limit:       爬行深度限制
        :temp_dir_path:     临时文件夹
        """
        super(SrcDownloader, self).__init__()

        self.kb = kb
        self.logger = logger
        self.executable = ' '.join([phantomjs_path, evaljs_path, ''])
        self.filetype_whitelist = filetype_whitelist
        self.depth_limit = depth_limit
        self.temp_dir_path = temp_dir_path

        self.exit_flag = False
        self.task_queue = []
        self.seconds_wait = 1  # 检测新加进来的URL

        # 线程分发器
        self.dispather = ParallelDispatcher(
            thread_num=thread_num,
            data_source=self.task_queue,
            execute_func=self.download_page,
            logger=self.logger,
            owner='Downloader',
            start_index=0,
            seconds_wait=2
        )

    def engine_start(self):
        """
        下载器主函数，下载源代码，并且保存到kb
        """
        self.log(['Engine started.'])

        url_count = 0
        while True:
            # 读取URL，读取完全返回None
            results = self.kb.read_data(URL, SRC_DOWNLOADER, url_count)
            if results is None:
                break

            # 添加到任务队列，由分发器分发
            if len(results) > 0:
                url_count += len(results)
                self.task_queue.extend(results)
                self.dispather.dispath_scan_task()

            # 检测到退出标志置位，退出
            if self.exit_flag:
                break
            time.sleep(self.seconds_wait)

        # 等待线程结束
        self.dispather.suicide()
        self.log(['Engine stopped.'])

    def download_page(self, task, thread_no):
        """
        线程执行函数，用phantomjs下载页面并且处理JS，结果保存到数据库
        :task:          (url, is_post，status_code, depth)
        :thread_no:     线程号
        """

        # 深度超过限制，文件类型不合法，或者是logout（这个也许有别的方法？）
        if (self.depth_limit < task[3] or
                not self.is_valid_filetype(task[0]) or
                re.compile(r'.*logout.*', re.IGNORECASE | re.DOTALL).search(task[0])):
            return
        self.log(['%d %s' % (task[3], task[0])])
        # shell命令，phantomjs，在参数前面增加P/G代表POST或者GET
        # batcmd = self.executable + ('"P' if task[1] == 2 else '"G') + task[0].replace('"',
        #                                                                               '""') + '" "' + os.getcwd() + '/EagleX/extra/temp"'
        batcmd = '{phantomjs}"{method}{url}" "{tmpdir}/EagleX/extra/temp"'.format(phantomjs=self.executable,
                                                                                  method=('P' if task[1] == 2 else 'G'),
                                                                                  url=task[0].replace('"', '""'),
                                                                                  tmpdir=os.getcwd())

        try:

            result = subprocess.check_output(batcmd, stderr=subprocess.STDOUT, shell=True, universal_newlines=True)
            # self.log([result])
        except subprocess.CalledProcessError as exc:
            self.exc = exc
            self.log(['[ERROR] phantomjs crashed, stderr output saved to CRASH.txt'])

            format_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            f = open(self.temp_dir_path + 'CRASH.txt', 'a')

            msg = '''======================={time}========================
                  ***********************************************************
                  {task}
                  ***********************************************************
                  ===========================================================
                  '''.format(time=format_time, task=task[0])
            f.write(msg)
            f.close()
            return

        # 数据库
        self.kb.save_data(SRC, (task[0], result, task[3]))

    def is_valid_filetype(self, url):
        """
        检查文件后缀是否合法
        :url:       目标URL
        :return:    True or False
        """
        extension = os.path.splitext(urlparse(url).path)[1].lstrip('.')
        # print extension
        if not extension:
            return True  # 如果没有匹配到后缀放行
        return self.filetype_whitelist.get(extension) is not None

    def exit(self):
        self.dispather.exit()
        self.exit_flag = True

    def log(self, msgs):
        self.logger.debug('Downloader', msgs)
