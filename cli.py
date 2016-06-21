# -*- encoding:utf-8 -*-

"""
File:       cli.py
Author:     magerx@paxmac.org
"""

from EagleX.MoguXSrv import MoguXSrv

if __name__ == '__main__':
    try:
        scan = MoguXSrv()
        scan.start(0)
    except Exception,e:
        print e
