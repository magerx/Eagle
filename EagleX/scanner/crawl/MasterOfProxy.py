# -*- encoding:utf-8 -*-

"""
File:       MasterOfProxy.py
Author:     magerx@paxmac.org
"""

#http://docs.mitmproxy.org/en/stable/scripting/libmproxy.html

import os
from mitmproxy import controller

from EagleX.scanner.util.URLUtility import extract_netloc_path
from EagleX.scanner.util.Header import *

class MasterOfProxy(controller.Master):
    """
    代理实现主类，转发请求，同时保存截获到的URL
    """

    def __init__(self, server, kb, allow_domain_re, restrict_path_re):
        """
        :server:        监听服务器
        :kb:            Universal KnowledgeBase
        :allow_domain:  允许的域名，本来应该在Crawler里了，现在还是单独放在这里
        :restrict_path: 限制目录，同上
        """
        controller.Master.__init__(self, server)

        self.kb = kb
        self.allow_domain_re = allow_domain_re.lstrip("*")
        self.restrict_path_re = restrict_path_re
        self.stickyhosts = {}

    def run(self):
        """
        线程执行函数
        """
        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, flow):
        """
        处理发起的请求
        """
        url, is_post = self.get_url_is_post(flow)

        # 如果符合域名要求，保存到数据库，暂时状态码先放0
        if self.is_valid_domain_path(url):
            self.kb.save_data(URL, [(url, is_post, 0, 0)])

        # 转发请求
        # hid = (flow.request.host, flow.request.port)
        # headers = dict(flow.request.headers)
        # print type(headers)
        # if headers.has_key("cookie"):# and flow.request.headers["cookie"]:
        #     self.stickyhosts[hid] = headers["cookie"]
        # elif hid in self.stickyhosts:
        #     flow.request.headers["cookie"] = self.stickyhosts[hid]
        flow.reply()

    def handle_response(self, flow):
        """
        返回包的处理，主要是要更新数据库里的状态码
        """
        # 更新请求状态码
        url, is_post = self.get_url_is_post(flow)
        self.kb.save_data(STATUS, (url, flow.response.status_code))

        # 转发请求
        # hid = (flow.request.host, flow.request.port)
        # if flow.response.headers.has_key("set-cookie"):#flow.response.headers["set-cookie"]:
        #     self.stickyhosts[hid] = flow.response.headers["set-cookie"]
        flow.reply()

    def is_valid_domain_path(self, url):
        """
        检查URL是否在允许的域名范围中，以及目录限制
        :return:        True，合法
        """
        netloc = extract_netloc_path(url)

        # 如果没有设置名单，那就万物皆允，否则就开始匹配
        # if  self.allow_domain_re.match('') or \
        #     self.allow_domain_re.match(netloc) and \
        #     self.restrict_path_re.match(path):
        if netloc.endswith(self.allow_domain_re):
            return True
        return False

    def get_url_is_post(self, flow):
        """
        从HTTPFlow中获得标准的URL拼接结果，和is_post
        :flow:      HTTPFlow对象
        :return:    (url, is_post)
        """
        r = flow.request

        # 得到拼接的URL
        is_post = 1 if len(r.content) > 0 else 0
        url = "{0}://{1}{2}{3}".format(r.scheme,r.host,('' if r.port == 80 else (':' + str(r.port))),flow.request.path)#r.scheme + '://' + r.host + ('' if r.port == 80 else (':' + str(r.port))) + flow.request.path
        if is_post == 1:
            url += ('&' if '?' in url else '?') + r.content

        return url, is_post
