# -*- encoding:utf-8 -*-

"""
File:       ClickProxy.py
Author:     magerx@paxmac.org
"""

from mitmproxy import proxy
from mitmproxy.proxy.server import ProxyServer
import time
import threading

from EagleX.scanner.crawl.MasterOfProxy import MasterOfProxy


class ClickProxy(object):
    """
    开启浏览器代理，人工加入额外的URL
    """

    def __init__(self, port, kb, logger, allow_domain_re, restrict_path_re):
        """
        :port:          监听端口
        :kb:            Universal KnowledgeBase
        :logger:        输出
        :allow_domain:  允许的域名，本来应该在Crawler里了，现在还是单独放在这里
        :restrict_path: 限制目录，同上
        """
        super(ClickProxy, self).__init__()

        config = proxy.ProxyConfig(port=port)
        server = ProxyServer(config)
        self.cproxy = MasterOfProxy(
            server=server,
            kb=kb,
            allow_domain_re=allow_domain_re,
            restrict_path_re=restrict_path_re
        )

        self.logger = logger
        self.exit_flag = False
        self.seconds_wait = 2

    def log(self, msgs):
        self.logger.debug('ClickProxy', msgs)

    def engine_start(self):
        """
        打开代理而已，检测到退出则关掉代理
        """
        self.log(['Engine started.'])
        thread = threading.Thread(target=self.cproxy.run)
        thread.setDaemon(True)
        thread.start()
        while not self.exit_flag:
            time.sleep(self.seconds_wait)
        self.cproxy.shutdown()
        self.log(['Engine stopped.'])

    def exit(self):
        self.exit_flag = True
