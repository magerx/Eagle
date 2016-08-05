# -*- encoding:utf-8 -*-

"""
File:       EyeOnKeyboard.py
Author:     magerx@paxmac.org
"""

import sys


class EyeOnKeyboard(object):
    """
    监听键盘，用于退出程序
    """

    def __init__(self, exit_str):
        """
        :exit_str:  退出的标志字符串
        """
        super(EyeOnKeyboard, self).__init__()
        self.exit_str = exit_str + '\n'

    def listen(self):
        """
        监听到指定字符串之后退出
        """
        _str = 'notexit'
        while _str != self.exit_str:
            _str = sys.stdin.readline()
