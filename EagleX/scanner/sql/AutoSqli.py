# -*- encoding:utf-8 -*-

"""
File:       AutoSqli.py
Author:     magerx@paxmac.org
Statement:  modified from AutoSqli.py by Manning
"""

import requests
import threading
import time
import json

class AutoSqli(object):
    """
    封装与sqlmapAPI的通信，新建任务到返回结果，整套
    """

    def __init__(self, server, target, logger, timeout=120, data='', referer='', cookie='', other_options={}, retries=3):
        """
        :server:        sqlmapAPI的监听地址
        :target:        目标URL
        :logger:        输出
        :timeout:       检测超时，默认120s
        :data:          post数据，默认空
        :referer:       referer，默认空
        :cookie:        cookie，默认空
        :other_options: 其它选项
        :retries:       失败后的重试次数，默认3
        """
        super(AutoSqli, self).__init__()

        self.timeout = timeout
        self.server = server
        if self.server[-1] != '/':
            self.server += '/'
        self.target = target
        self.data = data
        self.referer = referer
        self.cookie= cookie
        self.other_options = other_options
        self.retries = retries
        self.logger = logger

        self.taskid = ''
        self.payload = ''

        self.error_msg = ''
        self.retry_count = 0
        self.seconds_before_retry = 1
        self.seconds_before_check_status = 2
        self.exit_flag = False

    def log(self, msgs):
        self.logger.debug('AutoSqli', msgs)

    def exit(self):
        self.exit_flag = True

    def scan(self):
        """
        扫描器对外接口
        :return:    成功则返回payload，失败则None，主动杀死则空串
        """
        while (self.retry_count < self.retries):
            try:
                result = self.real_scan()
            except:
                # 出错重试
                self.log(['[ERROR] %s for %s' % (self.error_msg, self.target)])
                self.retry_count += 1
                if (self.retry_count < self.retries):
                    time.sleep(self.seconds_before_retry)
            else:
                break

        # 超过重试次数
        if (self.retry_count == self.retries):
            self.log(['[ERROR] Retried for %d times, abort on %s' % (self.retries, self.target)])
            return None
        # 主动杀死进程
        elif (self.retry_count == self.retries + 1):
            self.log(['Thread killed, abort on %s' % self.target])
            return ''

        return result

    def real_scan(self):
        """
        扫描主函数
        :return:    payload成功，None扫描失败，Exception进程失败
        """
        # 新建任务，失败则抛出异常
        try:
            if not self.task_new():
                raise NameError('')
        except:
            self.error_msg = 'Failed create task'
            raise

        # 设置任务选项，失败则抛出异常
        try:
            if not self.option_set():
                raise NameError('')
        except:
            self.error_msg = 'Failed set task options'
            self.task_delete()
            raise

        # 开始扫描，失败则抛出异常
        try:
            if not self.scan_start():
                raise NameError('')
        except:
            self.error_msg = 'Failed start scan'
            self.task_delete()
            raise

        succeed = True
        timeOut = False
        start_time = time.time()
        while True:
            # 检测到退出标志置位，杀死任务，退出，返回None
            if self.exit_flag:
                try:
                    self.scan_stop()
                    self.scan_kill()
                    self.task_delete()
                except:
                    pass

                # 这种情况是主动杀死
                self.retry_count = self.retries + 1
                return None

            if self.scan_status() == 1:     # 运行中每2秒检测一次状态
                time.sleep(self.seconds_before_check_status)
            elif self.scan_status() == 0:   # 运行结束
                break
            else:# 出错
                succeed = False
                break

            # 超时
            if time.time() - start_time > self.timeout:
                timeOut = True
                succeed = False
                break

        # 超时，或者任务状态异常，或者查询任务状态失败
        # 停止任务并且删除，不再理会异常，但给出自己的异常
        if not succeed:
            try:
                self.scan_stop()
                self.scan_kill()
                self.task_delete()
            except:
                pass
            if (timeOut):
                self.error_msg = 'Timeout while scanning'
            else :
                self.error_msg = 'Illegal task status'
            raise NameError('')

        # 任务成功完成，检查payload，失败则payload为None，否则是真的
        # 返回值并没有用，因为false的时候payload已经被设置成None了
        self.query_result()

        # 任务成功完成，删除任务
        try:
            self.task_delete()
        except:
            pass

        return self.payload

    def task_new(self):
        url = self.server + 'task/new'
        self.taskid = json.loads(requests.get(url).text)['taskid']
        return len(self.taskid) > 0

    def task_delete(self):
        url = self.server + 'task/' + self.taskid + '/delete'
        return json.loads(requests.get(url).text)['success']

    def scan_start(self):
        headers = {'Content-Type': 'application/json'}
        payload = {}

        url = self.server + 'scan/' + self.taskid + '/start'
        t = json.loads(requests.post(url, data=json.dumps(payload), headers=headers).text)

        return len(str(t['engineid'])) > 0 and t['success']

    def scan_status(self):
        """
        检查任务运行状态
        :return:    1运行，0停止，-1异常状态
        """
        try:
            url = self.server + 'scan/' + self.taskid + '/status'
            status = json.loads(requests.get(url).text)['status']
            return 1 if status == 'running' else (0 if status == 'terminated' else -1)
        except:
            return -1

    def query_result(self):
        """
        查询payload，失败则置为None
        """
        try:
            url = self.server + 'scan/' + self.taskid + '/data'
            self.payload = json.loads(requests.get(url).text)['data']
            if (len(self.payload) == 0):
                raise NameError('')
        except:
            self.payload = None
            return False
        return True

    def option_set(self):
        # 初始默认选项
        headers = {'Content-Type': 'application/json'}
        option = {  'url': self.target,
                    'data': self.data,
                    'referer': self.referer,
                    'cookie': self.cookie,
                    'smart': True
                }

        # 额外的选项覆盖默认的选项
        op_list = list(self.other_options)
        for key in op_list:
            option[key] = self.other_options[key]

        url = self.server + 'option/' + self.taskid + '/set'
        t = json.loads(requests.post(url, data=json.dumps(option), headers=headers).text)
        return t['success']

    def scan_stop(self):
        url = self.server + 'scan/' + self.taskid + '/stop'
        return json.loads(requests.get(url).text)['success']

    def scan_kill(self):
        url = self.server + 'scan/' + self.taskid + '/kill'
        return json.loads(requests.get(url).text)['success']
