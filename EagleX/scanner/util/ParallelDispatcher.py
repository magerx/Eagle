# -*- encoding:utf-8 -*-

"""
File:       ParallelDispatcher.py
Author:     magerx@paxmac.org
"""

import threading
import time


class ParallelDispatcher(object):
    """
    分发并管理线程执行，数据打包成元组
    """

    def __init__(self, thread_num, data_source, execute_func, logger, owner, start_index=0, seconds_wait=2):
        """
        :thread_num:    最大线程数
        :data_source:   源数据列表
        :execute_func:  线程执行的回调函数
        :logger:        输出
        :owner:         所属的类，用于输出
        :start_index:   源数据中开始的下标，往后按1递增
        :seconds_wait:  等待空闲线程时间
        """
        super(ParallelDispatcher, self).__init__()

        self.thread_num = thread_num
        self.data_source = data_source
        self.index_to_process = start_index
        self.execute_func = execute_func
        self.seconds_wait = seconds_wait
        self.logger = logger
        self.owner = owner
        self.thread_list = [None for i in xrange(self.thread_num)]
        self.exit_flag = False

    def dispath_scan_task(self):
        """
        分配任务给空闲进程，把目前的分配光
        """
        while self.index_to_process < len(self.data_source):
            freethread = self.get_free_thread_list()

            for x in freethread:
                self.dispath(self.index_to_process, x)
                self.index_to_process += 1
                if self.index_to_process >= len(self.data_source):
                    break

            # 检测到退出标志，退出
            if self.exit_flag:
                break
            time.sleep(self.seconds_wait)

    def dispath(self, task_no, thread_no):
        """
        分配task_no给thread_no的线程
        :task_no:   源数据的下标
        :thread_no: 线程数组的下标
        """
        # self.log(self.owner, ['Assign task %d to thread %d.' % (task_no, thread_no)])

        # 新建线程，参数为源数据列表
        self.thread_list[thread_no] = threading.Thread(
            target=self.execute_func,
            args=(self.data_source[task_no], thread_no)
        )
        self.thread_list[thread_no].start()

    def suicide(self):
        """
        等待所有线程退出
        """
        for x in self.thread_list:
            while x is not None and x.is_alive():
                time.sleep(self.seconds_wait)

    def get_free_thread_list(self):
        """
        获得空闲进程的列表
        """
        freethread = []
        for x in xrange(self.thread_num):
            if self.thread_list[x] is None or not self.thread_list[x].is_alive():
                freethread.append(x)
        return freethread

    def is_all_free(self):
        """
        是否全部线程都是空闲状态
        """
        for x in self.thread_list:
            if x is not None and x.is_alive():
                return False
        return True

    def log(self, owner, msgs):
        self.logger.debug(owner, msgs)

    def exit(self):
        self.exit_flag = True
