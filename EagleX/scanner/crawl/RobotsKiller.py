# -*- encoding:utf-8 -*-

"""
File:       Robots.py
Author:     magerx@paxmac.org
"""

import urllib2
import re
import threading
import time

from EagleX.scanner.util.URLUtility import url_process
from EagleX.scanner.util.Header import *

class Robots(object):
    """
    分析处理robots文件
    """

    def __init__(self, kb, logger):
        """
        :kb:        Universal KnowledgeBase
        :logger:    输出
        """
        super(Robots, self).__init__()

        self.kb = kb
        self.logger = logger

        self.seconds_wait = 2
        self.exit_flag = False

    def engine_start(self):
        """
        Robots文件扫描主引擎
        """
        self.log(['Engine started.'])

        while True:
            # 从数据库中取到未处理的domain，无需提供序号
            # 结束了则返回None
            results = self.kb.read_data(DOMAIN, ROBOTS_KILLER, 0)
            if results is None:
                break

            # 处理domain列表
            if len(results) > 0:
                self.handle_robots_files(results)

            # 检测到退出标志置位，退出
            if self.exit_flag:
                break
            time.sleep(self.seconds_wait)

        self.log(['Engine stopped.'])

    def handle_robots_files(self, domain_list):
        """
        访问domain列表，分析每一个ROBOTS，结果保存到数据库中
        :domain_list:   已发现域名列表
        """
        urls = []
        for x in domain_list:
            new_urls = self.parse_robots_file(x + '/robots.txt')
            for i in xrange(len(new_urls)):
                new_urls[i] = new_urls[i].rstrip(chr(0x0d))
            urls.extend([(url, 0, 200, 0) for url in new_urls])

        self.kb.save_data(URL, urls)

    def parse_robots_file(self, url):
        """
        分析robots文件，导出urls
        :url:       目标域名
        :return:    分析出来的URL
        """
        robots = ''
        try:
            robots = urllib2.urlopen(url).read()
        except:
            robots = ''
        pattern = re.compile(r'(?:Disallow|Allow|Sitemap):[ ]*([^ \n]*)')
        paths = pattern.findall(robots)

        # 返回URLS，不能包含*跟?，这个处理有点粗糙，可以改进
        return [url_process(path, url) for path in paths \
                if (not '*' in path and not '?' in path)]

    def exit(self):
        self.exit_flag = True

    def log(self, msgs):
        self.logger.debug('Robots', msgs)
