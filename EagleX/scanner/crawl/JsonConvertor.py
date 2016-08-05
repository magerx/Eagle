# -*- encoding:utf-8 -*-

"""
File:       JsonConvertor.py
Author:     magerx@paxmac.org
"""

import json
from urlparse import urlparse
from EagleX.scanner.util.Header import *


class JsonConvertor(object):
    """
    运行中将发现的URL转成目录树的JSON格式
    """

    def __init__(self, kb):
        """
        :kb:    Universal KnowledgeBase
        """
        super(JsonConvertor, self).__init__()

        self.data = []
        self.kb = kb

    def add_new_url(self, url, is_post, code):
        """
        添加新的url到数据集中
        :url:       新的URL
        :is_post:   是否为POST
        :code:      状态码
        """
        # 分割URL，以及POST信息
        url = urlparse(url)
        f_domain = url.scheme + '://' + url.netloc
        f_query = ('?' if len(url.query) > 0 else '') + url.query + (' - POST' if is_post == 2 else '')
        f_path = url.path

        # 添加到对应的域名下面去，如果没有就新建一个
        i = self.find_node_with_name(self.data, f_domain)
        if i != -1:
            self.data[i]['children'] = self.parse_path(self.data[i]['children'], f_path, f_query, code)
            return

        self.data.append({'name': f_domain, 'children': [], 'open': 'true'})
        self.data[-1]['children'] = self.parse_path(self.data[-1]['children'], f_path, f_query, code)

    def parse_path(self, node, path, query, code):
        """
        递归处理path，添加到数据集中
        :node:      当前节点
        :path:      路径
        :query:     查询
        :code:      状态码
        :return:    操作完成的节点
        """
        path = path.lstrip('/').rstrip('/')

        # 没有次级目录
        if (path.find('/') == -1):
            if (len(path) == 0):  # 根目录
                node.append({'name': '/' + query + ((' - ' + str(code)) if code != 0 else '')})

            elif (path.find('.') == -1):  # 目录
                i = self.find_node_with_name(node, path)
                if (i != -1):
                    # node[i]['children'].append({'name':'/' + query + ((' - ' + str(code)) if code != 0 else '')})
                    pass
                else:
                    node.append({'name': path, 'children': []})
                    # node[-1]['children'].append({'name':'/' + query + ((' - ' + str(code)) if code != 0 else '')})

            else:  # 文件
                node.append({'name': path + query + ((' - ' + str(code)) if code != 0 else '')})
            return node

        # 分离出当前目录
        directory = path[0:path.find('/')]
        if ('.' in directory or ';' in directory):
            return node
        path = path[path.find('/') + 1:]

        # 添加到数据集中
        i = self.find_node_with_name(node, directory)
        if (i != -1):
            node[i]['children'] = self.parse_path(node[i]['children'], path, query, code)
            return node
        node.append({'name': directory, 'children': []})
        node[-1]['children'] = self.parse_path(node[-1]['children'], path, query, code)

        return node

    def find_node_with_name(self, node, name):
        """
        根据目录名寻找对应的节点
        :node:      当前节点
        :name:      节点名字
        :return:    节点的下标，-1找不到
        """
        for i in xrange(0, len(node)):
            if (cmp(node[i]['name'], name) == 0):
                return i
        return -1

    def save_to_database(self, extra):
        """
        保存数据集的内容到数据库中，zTree可以读取
        :extra:     数据前缀
        """
        self.kb.save_data(JSON, extra + json.dumps(self.data))
