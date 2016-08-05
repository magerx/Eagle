# -*- encoding:utf-8 -*-

"""
File:       VulScanner.py
Author:     magerx@paxmac.org
"""

import threading
import time
import sys
from ConfigParser import ConfigParser

from EagleX.scanner.sql.SqlScanner import SqlScanner
from EagleX.scanner.crawl.Crawler import Crawler
from EagleX.scanner.xss.XssScanner import XssScanner
from EagleX.scanner.bruteforce.FormAuth import FormAuth
from EagleX.scanner.lfi.LFIScanner import LFIScanner
from EagleX.scanner.cmd_exec.CMDExec import CMDExec
from EagleX.scanner.code_exec.CODEExec import CODEExec
from EagleX.scanner.url_redirect.UrlRedirect import UrlRedirect
from EagleX.scanner.info_leakage.INFOLeakage import INFOLeakage

from EagleX.scanner.util.KnowledgeBase import KnowledgeBase
from EagleX.scanner.util.Logger import Logger


class VulScanner(object):
    """
    主扫描器类，新建全局输出和数据库，启动爬虫以及各种扫描器
    """

    def __init__(self, config_file):
        """
        :config_file:       config_file_path
        解析配置文件
        """
        super(VulScanner, self).__init__()

        self.config = ConfigParser()
        self.config.read(config_file)

        # 全局数据库及Cookie
        self.kb = KnowledgeBase(self.config.get('Scanner', 'database_path'))
        self.cookie = self.config.get('Cookie', 'cookie')
        self.temp_dir_path = self.config.get('Scanner', 'temp_dir_path')

        # 输出
        redirect = self.config.get('Scanner', 'output_file_path')
        redirect = sys.stdout if redirect == '' else open(redirect, 'w')
        self.logger = Logger(debug=True, redirect=redirect, kb=self.kb)

        # 检测线程状态的间隔
        self.seconds_wait = 2
        self.exit_flag = False

        # 定制启动的模块，得到模块列表和所有模块的初始化
        module_list = {'Crawler': self.init_crawler,
                       'XSSScanner': self.init_xss_scanner,
                       'SQLScanner': self.init_sql_scanner,
                       'FormAuth': self.init_form_auth,
                       'LFIScanner': self.init_lfi_scanner,
                       'CMDExec': self.init_cmd_exec,
                       'CODEExec': self.init_code_exec,
                       'URLRedirect': self.init_url_redirect,
                       'INFOLeakage': self.init_info_leakage,
                       }

        modules_init_func = []
        # 对配置文件中启用的模块进行初始化
        for active_module in self.config.get('Scanner', 'modules').split('|'):
            if module_list.get(active_module) is not None:
                modules_init_func.append(module_list[active_module])
        self.modules = [init() for init in modules_init_func]

    def log(self, msgs):
        self.logger.debug('Scanner', msgs)

    def init_crawler(self):
        """
        初始化爬虫
        :return:    爬虫模块对象，失败返回None
        """
        try:
            depth_limit = int(self.config.get('Crawler', 'depth_limit'))
            start_url = self.config.get('Crawler', 'start_url')
            allow_domain = self.config.get('Crawler', 'allow_domain')
            restrict_path = self.config.get('Crawler', 'restrict_path')

            temp = self.config.get('Crawler', 'filetype_whitelist').split('|')
            filetype_whitelist = {}
            for t in temp:
                filetype_whitelist[t] = 0

            evaljs_path = self.config.get('Crawler', 'evaljs_path')
            phantomjs_path = self.config.get('Crawler', 'phantomjs_path')
            thread_num_download = int(self.config.get('Crawler', 'thread_num_download'))
            dir_dict_paths = self.config.get('Crawler', 'dir_dict_paths').split('|')
            thread_num_burst = int(self.config.get('Crawler', 'thread_num_burst'))
            click_proxy_port = int(self.config.get('Crawler', 'click_proxy_port'))
            modules = self.config.get('Crawler', 'modules').split('|')
        except Exception, exc:
            self.log(['[ERROR] Failed parsing config for crawler, traceback:', exc])
            return None

        return Crawler(depth_limit=depth_limit,
                       logger=self.logger,
                       click_proxy_port=click_proxy_port,
                       start_url=start_url,
                       allow_domain=allow_domain,
                       restrict_path=restrict_path,
                       filetype_whitelist=filetype_whitelist,
                       evaljs_path=evaljs_path,
                       phantomjs_path=phantomjs_path,
                       thread_num_download=thread_num_download,
                       kb=self.kb,
                       dir_dict_paths=dir_dict_paths,
                       thread_num_burst=thread_num_burst,
                       cookie=self.cookie,
                       temp_dir_path=self.temp_dir_path,
                       modules=modules
                       )

    def init_sql_scanner(self):
        """
        初始化SQL注入扫描器
        :return:    SQL扫描器模块对象，失败返回None
        """
        try:
            sqlmapapi_path = self.config.get('SQLScanner', 'sqlmapapi_path')
            sqlmapapi_server_port = int(self.config.get('SQLScanner', 'sqlmapapi_server_port'))
            sqlmapapi_server_addr = self.config.get('SQLScanner', 'sqlmapapi_server_addr')
            thread_num = int(self.config.get('SQLScanner', 'thread_num'))
        except Exception, exc:
            self.log(['[ERROR] Failed parsing config for SQLscanner, traceback:', exc])
            return None

        return SqlScanner(kb=self.kb,
                          sqlmapapi_path=sqlmapapi_path,
                          sqlmapapi_port=sqlmapapi_server_port,
                          logger=self.logger,
                          cookie=self.cookie,
                          sqlmapapi_addr=sqlmapapi_server_addr,
                          thread_num=thread_num,
                          temp_dir_path=self.temp_dir_path
                          )

    def init_xss_scanner(self):
        """
        初始化XSS扫描器
        :return:    XSS扫描器模块对象，失败返回None
        """
        try:
            thread_num_dom = int(self.config.get('XSSScanner', 'thread_num_dom'))
            thread_num_reflected = int(self.config.get('XSSScanner', 'thread_num_reflected'))
            modules = self.config.get('XSSScanner', 'modules').split('|')
        except Exception, exc:
            self.log(['[ERROR] Failed parsing config for XSSscanner, traceback:', exc])
            return None

        return XssScanner(kb=self.kb,
                          logger=self.logger,
                          thread_num_dom=thread_num_dom,
                          thread_num_reflected=thread_num_reflected,
                          cookie=self.cookie,
                          modules=modules
                          )

    def init_lfi_scanner(self):
        """
        初始化LFI扫描器
        :return:    LFI扫描器模块对象，失败返回None
        """
        try:
            thread_num = int(self.config.get('LFIScanner', 'thread_num'))
        except Exception, exc:
            self.log(['[ERROR] Failed parsing config for LFIscanner, traceback:', exc])
            return None

        return LFIScanner(kb=self.kb,
                          logger=self.logger,
                          thread_num=thread_num,
                          cookie=self.cookie
                          )

    def init_cmd_exec(self):
        """
        初始化远程命令执行扫描器
        :return:    CMD执行扫描器模块对象，失败返回None
        """
        try:
            thread_num = int(self.config.get('CMDExec', 'thread_num'))
        except Exception, exc:
            self.log(['[ERROR] Failed parsing config for CMDExecscanner, traceback:', exc])
            return None

        return CMDExec(kb=self.kb,
                       logger=self.logger,
                       thread_num=thread_num,
                       cookie=self.cookie
                       )

    def init_code_exec(self):
        """
        初始化远程命令执行扫描器
        :return:    代码执行扫描器模块对象，失败返回None
        """
        try:
            thread_num = int(self.config.get('CODEExec', 'thread_num'))
        except Exception, exc:
            self.log(['[ERROR] Failed parsing config for CODEExecscanner, traceback:', exc])
            return None

        return CODEExec(kb=self.kb,
                        logger=self.logger,
                        thread_num=thread_num,
                        cookie=self.cookie
                        )

    def init_url_redirect(self):
        """
        初始化URL跳转扫描器
        :return:    URL跳转扫描器模块对象，失败返回None
        """
        try:
            thread_num = int(self.config.get('URLRedirect', 'thread_num'))
        except Exception, exc:
            self.log(['[ERROR] Failed parsing config for URLRedirectscanner, traceback:', exc])
            return None

        return UrlRedirect(kb=self.kb,
                           logger=self.logger,
                           thread_num=thread_num,
                           cookie=self.cookie
                           )

    def init_info_leakage(self):
        """
        初始化信息泄露扫描器
        :return:    信息泄露扫描器模块对象，失败返回None
        """
        try:
            thread_num = int(self.config.get('INFOLeakage', 'thread_num'))
        except Exception, exc:
            self.log(['[ERROR] Failed parsing config for INFOLeakagescanner, traceback:', exc])
            return None

        return INFOLeakage(kb=self.kb,
                           logger=self.logger,
                           thread_num=thread_num,
                           cookie=self.cookie
                           )

    def init_form_auth(self):
        """
        初始化表单猜解
        :return:    FormAuth对象，失败则为None
        """
        try:
            user_dict = self.config.get('FormAuth', 'user_dict')
            pass_dict = self.config.get('FormAuth', 'pass_dict')
        except Exception, exc:
            self.log(['[ERROR] Failed parsing config for FormAuth, traceback:', exc])
            return None

        return FormAuth(kb=self.kb,
                        logger=self.logger,
                        user_dict=user_dict,
                        pass_dict=pass_dict
                        )

    def engine_start(self):
        """
        扫描启动主函数，启动扫描，监听线程是否退出
        """

        # 模块初始化失败则返回None，退出
        for module in self.modules:
            if module is None:
                self.log(['[ERROR] Failed parsing config file, VulScanner main thread exit.'])
                return

        # 启动线程们
        thread_list = [threading.Thread(target=module.engine_start) for module in self.modules]
        for thread in thread_list:
            thread.start()

        # 线程之间因为互相依赖数据，目前处于将会一直卡死不会自动退出的情形
        # 需要上级线程间接杀死本线程
        while True:
            if self.exit_flag:
                self.kb.clean_up()
                for module in self.modules:
                    module.exit()
                break

            time.sleep(self.seconds_wait)

        return

    def exit(self):
        self.exit_flag = True
