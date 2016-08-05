# -*- encoding:utf-8 -*-

"""
File:       EagleXSrv.py
Author:     magerx@paxmac.org
"""

import threading
import time
import sys
import os
from EagleX.scanner.core.VulScanner import VulScanner
from EagleX.scanner.util.EyeOnKeyboard import EyeOnKeyboard

# 配置文件路径
CONFIG_FILE = os.path.dirname(__file__) + '/EagleXConfig.ini'


class EagleXSrv(object):
    """
    外面再套层壳
    """

    def __init__(self):
        super(EagleXSrv, self).__init__()
        self.scanner = None
        self.scanner_thread = None

    def start(self, type):
        """
        启动整个扫描流程
        :type:      0命令行使用，监听键盘
                    1WEB端使用，自动结束
        """
        # 启动扫描器
        self.scanner = VulScanner(CONFIG_FILE)
        self.scanner_thread = threading.Thread(target=self.scanner.engine_start)
        self.scanner_thread.start()

        # 监听键盘，监听到关键字或Ctrl+C后退出，或者随主线程退出
        try:
            if type == 0:
                eye = EyeOnKeyboard('exit')
                eye_thread = threading.Thread(target=eye.listen)
                eye_thread.setDaemon(True)
                eye_thread.start()

                # 等待扫描器结束
                while self.scanner_thread.is_alive() and eye_thread.is_alive():
                    time.sleep(1)
                self.scanner.exit()

        except KeyboardInterrupt:
            self.scanner.exit()
            sys.exit()

    def exit(self):
        """
        关闭扫描器
        """
        if self.scanner is not None:
            self.scanner.exit()
            while self.scanner_thread.is_alive():
                time.sleep(0.5)
