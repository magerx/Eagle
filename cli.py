# -*- encoding:utf-8 -*-

"""
File:       cli.py
Author:     magerx@paxmac.org
"""

from EagleX.EagleXSrv import EagleXSrv

if __name__ == '__main__':
    try:
        scan = EagleXSrv()
        scan.start(0)
    except Exception, e:
        print e
