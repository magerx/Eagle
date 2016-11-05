# -*- encoding:utf-8 -*-

"""
File:       PayloadSender.py
Author:     magerx@paxmac.org
Modify:     2016-03-18
"""

import urllib
import urllib2
import time
import pycurl
from EagleX.scanner.util.Gziphandle import ContentEncodingProcessor

"""
发送Payload的函数，目前只有XSS用，不过可以定制
"""


def send_payload(url, is_post, querys, payload, check_func, cookie):
    """
    发送Payload给URL，并检测结果
    :url:           目标URL
    :is_post:       post
    :query:         查询，列表
    :payload:       payload
    :check_func:    验证payload是否成功的函数
    :cookie:        cookie
    :return:        可以注入的参数的index，没有则返回-1
    """
    for i in xrange(len(querys)):
        _ = time.time()
        src = send_request_with_payload(url, is_post, querys, i, payload, cookie)
        if check_func(payload, src, _):
            return i
    return -1


def send_request_with_payload(url, is_post, querys, index, payload, cookie):
    """
    发送Payload给URL，返回页面源码
    :url:           目标URL
    :is_post:       post
    :query:         查询，列表
    :index:         payload插入的位置
    :payload:       payload
    :cookie:        cookie
    :return:        返回的源代码
    """
    # URL编码只对除了payload之外的参数起作用，payload不做URL编码
    # 用payload替换需要测试的参数值,其余参数值用原值
    query = {}
    for i in xrange(len(querys)):
        if i != index:
            query[querys[i][0]] = querys[i][1]

    para = urllib.urlencode(query)
    para += '&' if len(para) > 0 else ''
    para += '{0}={1}'.format(querys[index][0], payload)
    # print para
    return send_common_request(url, is_post, cookie, para)


def send_common_request(url, is_post, cookie, para=''):
    """
    发送正常的WEB请求，返回页面
    :url:       目标URL
    :is_post:   是否是POST
    :cookie:    cookie
    """
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:42.0) Gecko/20100101 Firefox/42.0',
               'Cookie': cookie
               }
    # dns cache
    # socket.getaddrinfo = new_getaddrinfo

    try:
        encoding_support = ContentEncodingProcessor()
        opener = urllib2.build_opener(encoding_support, urllib2.HTTPHandler)
        urllib2.install_opener(opener)
        if is_post == 2:  # post
            # url, query = url.split('?', 1)
            return urllib2.urlopen(urllib2.Request(url, para, headers=headers)).read()
        else:
            return urllib2.urlopen(urllib2.Request('?'.join([url, para]), headers=headers)).read()
    except:
        return ''


def curl(source_url, is_post, cookie):
    """
    通过pycurl发送正常的WEB请求，返回页面
    :source_url:       目标URL
    :is_post:   是否是POST
    :cookie:    cookie
    """
    buffer = BytesIO()
    c = pycurl.Curl()
    c.setopt(c.ENCODING, 'gzip,deflate')
    c.setopt(c.COOKIE, cookie)
    c.setopt(c.USERAGENT, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:42.0) Gecko/20100101 Firefox/42.0')
    try:
        if is_post == 2:  # post
            url, query = source_url.split('?', 1)
            c.setopt(c.URL, url)
            c.setopt(c.POSTFIELDS, query)
        else:
            c.setopt(c.URL, source_url)
        c.setopt(c.WRITEDATA, buffer)
        c.perform()
        c.close()
        return buffer.getvalue()
    except:
        return ''
