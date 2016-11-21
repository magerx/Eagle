# -*- encoding:utf-8 -*-

"""
File:       Crawler.py
Author:     magerx@paxmac.org
Modify:     2016-03-29
"""

import threading
import time
import re
from EagleX.scanner.crawl.ClickProxy import ClickProxy
from EagleX.scanner.crawl.RobotsKiller import Robots
from EagleX.scanner.crawl.SrcDownloader import SrcDownloader
from EagleX.scanner.crawl.JsonConvertor import JsonConvertor
from EagleX.scanner.bruteforce.DirBurster import DirBurster
from EagleX.scanner.util.Header import *
from EagleX.scanner.util.ParseUtility import parse_page
from EagleX.scanner.util.URLUtility import extract_netloc_path


class Crawler(object):
    """
    爬虫类，目录猜解，Robots解析等
    """

    def __init__(self, depth_limit, logger, click_proxy_port, start_url, allow_domain, restrict_path,
                 filetype_whitelist, evaljs_path, phantomjs_path, thread_num_download, kb, dir_dict_paths,
                 thread_num_burst, cookie, temp_dir_path, modules):
        """
        :depth_limit:           爬行深度
        :logger:                输出
        :click_proxy_port:      代理服务器端口
        :start_url:             开始的URL
        :allow_domain:          允许域名
        :restrict_path:         限制目录
        :filetype_whitelist:    文件类型白名单
        :evaljs_path:           js路径
        :phantomjs_path:        phantomjs路径
        :thread_num_download:   下载线程数
        :kb:                    Universal KnowledgeBase
        :dir_dict_paths:        目录猜解字典路径
        :thread_num_burst:      目录猜解线程数
        :cookie:                cookie
        :temp_dir_path:         临时文件夹
        :modules:               模块列表
        """
        super(Crawler, self).__init__()

        self.logger = logger
        self.kb = kb
        self.start_url = start_url
        self.allow_domain = allow_domain.lstrip("*")
        self.restrict_path = restrict_path

        # 传参cookie保存到文件中，phantomjs读取
        f = open(temp_dir_path + 'cookie.for.phantomjs.txt', 'w')
        f.write("{0};{1}".format(self.allow_domain, cookie))
        f.close()

        # 限定爬行域名和目录，目前通过正则
        # self.regulex_domain_path()

        # 模块们的初始化函数和对应的参数
        module_list = {'DOWNLOAD': self.init_downloader,
                       'DIRBURST': self.init_dir_burst,
                       'ROBOTS': self.init_robots,
                       'PROXY': self.init_click_proxy
                       }

        args_list = {'DOWNLOAD': (
            kb, phantomjs_path, evaljs_path, logger, thread_num_download, filetype_whitelist, depth_limit,
            temp_dir_path),
            'DIRBURST': (kb, thread_num_burst, dir_dict_paths, logger),
            'ROBOTS': (kb, logger),
            'PROXY': (click_proxy_port, kb, logger, self.allow_domain, self.restrict_path)
        }

        # 默认启动下载器，添加到启动列表
        if 'DOWNLOAD' not in modules:
            modules.append('DOWNLOAD')

        # 定制启动的模块，得到模块列表并启动
        modules_init_func = []
        for active_module in modules:
            if module_list.get(active_module) is not None:
                modules_init_func.append((module_list[active_module], args_list[active_module]))
        self.module_list = [init(arg) for init, arg in modules_init_func]
        self.thread_list = [threading.Thread(target=module.engine_start) for module in self.module_list]

        # JSON转换模块，用于TreeView展示，不涉及到多少数据量，就在主线程中执行
        self.json_convertor = JsonConvertor(
            kb=kb
        )

        self.exit_flag = False
        self.seconds_wait = 1

    def init_click_proxy(self, (port, kb, logger, allow_domain, restrict_path)):
        """
        初始化一个click_proxy，参数即所需的东西
        :return:    ClickProxy对象
        """
        return ClickProxy(port=port,
                          kb=kb,
                          logger=logger,
                          allow_domain_re=allow_domain,
                          restrict_path_re=restrict_path
                          )

    def init_downloader(self,
                        (kb, phantomjs_path, evaljs_path, logger, thread_num, filetype_whitelist, depth_limit, temp_dir_path)):
        """
        初始化一个downloader，参数即所需的东西
        :return:    SrcDownloader对象
        """
        return SrcDownloader(kb=kb,
                             phantomjs_path=phantomjs_path,
                             evaljs_path=evaljs_path,
                             logger=logger,
                             thread_num=thread_num,
                             filetype_whitelist=filetype_whitelist,
                             depth_limit=depth_limit,
                             temp_dir_path=temp_dir_path
                             )

    def init_robots(self, (kb, logger)):
        """
        初始化一个robots，参数即所需的东西
        :return:    Robots对象
        """
        return Robots(kb=kb,
                      logger=logger
                      )

    def init_dir_burst(self, (kb, thread_num, dic_paths, logger)):
        """
        初始化一个目录猜解器，参数即所需的东西
        :return:    DirBurster对象
        """
        return DirBurster(kb=kb,
                          thread_num=thread_num,
                          dic_paths=dic_paths,
                          logger=logger
                          )

    def engine_start(self):
        """
        扫描器主函数
        """
        self.log(['Engine started.'], DEBUG)

        # 初始化已发现的URL
        if self.is_valid_domain_path(self.start_url):
            self.kb.save_data(URL, [(self.start_url, 0, 0, 0)])

        # 逐一启动子模块
        for x in self.thread_list:
            x.start()

        json_count = 0
        while True:
            # 从数据库中读取已爬取的页面源代码，返回(url, src, depth)
            # None，程序终结
            # ''，没有新的页面
            results = self.kb.read_data(SRC, CRAWLER, 0)
            # print results
            if results is None:
                break
            elif results == '':
                end_tag += 1
                time.sleep(5)

            # 分析页面，保存URL，更新当前页面的状态码
            if results != '':
                code, urls, login_forms = parse_page(results[0], results[1], results[2])
                self.kb.save_data(URL,
                                  [url for url in urls if self.is_valid_domain_path(url[0])])
                self.kb.save_data(STATUS, (results[0], code))
                self.kb.save_data(LOGIN_FORM, login_forms)

            # 重新读取新发现的URL，同样返回None为程序终结
            results = self.kb.read_data(URL, CRAWLER, json_count)
            if results is None:
                break
            elif not results and end_tag == 1:
                results = self.kb.read_data(URL, CRAWLER, json_count)
                if not results:
                    end_tag += 1

            # 将结果处理成JSON格式，保存到JSON数据库中
            if len(results) > 0:
                json_count += len(results)
                for result in results:
                    self.json_convertor.add_new_url(result[0], result[1], result[2])
                self.json_convertor.save_to_database('')
                # print self.json_convertor

            # 检测到退出标志置位，退出
            if self.exit_flag or end_tag == 2:
                break
            time.sleep(self.seconds_wait)

        # 清理现场，保存JSON并多存一个空格，网页端的结束标志
        self.clean_up()
        self.json_convertor.save_to_database(' ')

        self.log(['Engine stopped.'], DEBUG)

    def clean_up(self):
        """
        清理现场，关闭子模块，等待线程结束
        """
        for module in self.module_list:
            module.exit()

        for x in self.thread_list:
            while x.is_alive():
                time.sleep(0.5)

    def is_valid_domain_path(self, url):
        """
        检查URL是否在允许的域名范围中，以及目录限制
        :return:        True，合法
        """
        netloc = extract_netloc_path(url)

        # 如果没有设置名单，那就万物皆允，否则就开始匹配
        if netloc.endswith(self.allow_domain):
            return True
        return False

    def exit(self):
        self.exit_flag = True

    def log(self, msgs, debug):
        if debug:
            self.logger.debug('Crawler', msgs)
        else:
            self.logger.info('Crawler', msgs)
