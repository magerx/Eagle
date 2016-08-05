# -*- encoding:utf-8 -*-

"""
File:       FormAuth.py
Author:     magerx@paxmac.org
"""

import urllib2
import time
from EagleX.scanner.util.Header import *


class FormAuth(object):
    """
    登录表单的爆破，想想一个站也没几个登录表单，就一个线程开起来搞
    """

    def __init__(self, kb, logger, user_dict, pass_dict):
        """
        :kb:        Universal KnowledgeBase
        :logger:    输出
        :user_dict: 用户名的字典
        :pass_dict: 密码的字典
        """
        super(FormAuth, self).__init__()

        self.kb = kb
        self.logger = logger

        # 把字典转成列表存起来先
        self.u_list = open(user_dict, 'r').readlines()
        for i in xrange(len(self.u_list)):
            self.u_list[i] = self.u_list[i].replace('\r', '').replace('\n', '')
        self.p_list = open(pass_dict, 'r').readlines()
        for i in xrange(len(self.p_list)):
            self.p_list[i] = self.p_list[i].replace('\r', '').replace('\n', '')

        self.seconds_wait = 2
        self.exit_flag = False
        self.visited = {}

    def engine_start(self):
        """
        表单弱口令破解
        """
        self.log(['Engine started.'], DEBUG)

        while True:
            # 数据库中取得爬取到的表单, (url with '?', [(name, value, type), ...])
            # 结束了则返回None
            results = self.kb.read_data(LOGIN_FORM, FORM_AUTH, 0)
            if results is None:
                break

            # 如果又None则代表没有数据，否则测试这个表单
            if not (results[0] is None or results[1] is None):
                self.brute_login_form(results)

            # 检测到退出标志置位，退出
            if self.exit_flag:
                break
            time.sleep(self.seconds_wait)

        self.log(['Engine stopped.'], DEBUG)

    def exit(self):
        self.exit_flag = True

    def log(self, msgs, debug):
        if debug:
            self.logger.debug('FormAuth', msgs)
        else:
            self.logger.info('FormAuth', msgs)

    def brute_login_form(self, task):
        """
        猜解登录表单
        :task:      (url, form)
                这里form只有两种可能，一个text一个password，或者单单一个password
                当然可能其他比如hidden的类型，其他就全部交上去
        """
        url, forms = task
        url = url if (url.find('?') == -1) else url[0:url.find('?')]

        # 已经爬取过了就不做了
        if self.visited.get(url) != None:
            return
        self.visited[url] = 0

        # 因为已经确定只有1+1，或者1的密码
        # 所以直接记录对应的name
        user = passwd = None
        inputs = {}
        for form in forms:
            # 原来的列表转成dict
            inputs[form[0]] = form[1]

            # 记录name，没有则保持None
            if form[2] == 'text':
                user = form[0]
            elif form[2] == 'password':
                passwd = form[0]

        u_list = self.u_list if user is not None else []
        p_list = self.p_list if passwd is not None else []

        self.do_brute_login_form(url, inputs, u_list, p_list, user, passwd)

    def do_brute_login_form(self, url, para, u_list, p_list, user, passwd):
        """
        猜解登录表单
        :url:       目标URL
        :para:      参数
        :u_list:    用户名字典
        :p_list:    密码字典
        :user:      表单里用户名的name
        :passwd:    表单里密码的name
        """
        # 如果有用户名，把其置成随便值，获得错误页面
        if user is not None:
            para[user] = 'lalalalala'
        para[passwd] = ''
        login_fail_page = self.send_request(url, para)

        # 分成两种情况，用户名+密码，密码
        # 循环遍历字典，找到后保存到数据库里
        if user is not None:
            for u in u_list:
                para[user] = u
                for p in p_list:
                    para[passwd] = p

                    # 得到页面，并且跟错误页面比较
                    login_page = self.send_request(url, para)
                    if not self.is_similar(login_page, login_fail_page):
                        self.log(['[WEAKPASS] %s' % url,
                                  '    [PAYLOAD] user-pass %s' % ':'.join([u, p])], not DEBUG)
                        self.kb.save_data(BRUTE, (url, str(para), u + ':' + p, 'FormAuth'))
                        return
        else:
            for p in p_list:
                para[passwd] = p
                login_page = self.send_request(url, para)
                if not self.is_similar(login_page, login_fail_page):
                    self.log(['[WEAKPASS] %s' % url,
                              '    [PAYLOAD] pass-only %s' % p], not DEBUG)
                    self.kb.save_data(BRUTE, (url, str(para), 'NONE:' + p, 'FormAuth'))
                    return

        self.log(['No user pass combination found at %s' % url], DEBUG)

    def send_request(self, url, para):
        """
        发送post请求
        :url:       URL
        :para:      参数表
        :return:    页面源代码
        """
        headers = {'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
        try:
            query = '&'.join([(p[0] + '=' + p[1]) for p in para.items()])
            return urllib2.urlopen(urllib2.Request(url, query, headers=headers)).read()
        except:
            return ''

    def is_similar(self, a, b):
        """
        判断两个字符串是否相似，用了w3af里的方法
        :a:         字符串A
        :b:         字符串B
        :return:    是否相似
        """
        # 用空格分隔开，判断交集的长度对于整个长度的比例，高于0.6算是相似
        set_a = set(a.split(' '))
        set_b = set(b.split(' '))
        ratio = 1.0 * len(set_a.intersection(set_b)) / max(len(set_a), len(set_b))
        return ratio > 0.6
