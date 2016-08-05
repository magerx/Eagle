# -*- encoding:utf-8 -*-

"""
File:       XssPayloads.py
Author:     magerx@paxmac.org
"""

import re
from random import randint

"""
XSS的Payload以及对应的函数
"""

# 反射型用
_all_char = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'


def replace_randomize(payload):
    length = randint(10, 15)
    randstr = ''.join([_all_char[randint(0, len(_all_char) - 1)] for _ in xrange(length)])
    return payload.replace('RANDOMIZE', randstr)


PAYLOADS = ['RANDOMIZE</*-"\'`=>RANDOMIZE',
            'RANDOMIZE\'>RANDOMIZE',
            'RANDOMIZE">RANDOMIZE',
            'RANDOMIZE>//RANDOMIZE',
            "RANDOMIZE';//RANDOMIZE",
            "RANDOMIZE\";//RANDOMIZE"
            ]

# DOM型
JS_FUNCTIONS = ('document.write',
                'document.writeln',
                'document.innerHTML',
                'document.execCommand',
                'document.open',
                'window.open',
                'eval',
                'window.execScript',
                'setTimeout',
                'setInterval',
                'setAttribute'
                )

JS_FUNCTION_CALLS = [re.compile(js_f + ' *\((.*?)\)', re.IGNORECASE) for js_f in JS_FUNCTIONS]

DOM_USER_CONTROLLED = ('document.URL',
                       'document.URLUnencoded',
                       'document.location',
                       'document.referrer',
                       'document.documentURI',
                       'window.location',
                       'location.hash',
                       'location.href',
                       'location.search'
                       )

# Compile the regular expressions
_script_re = re.compile('< *script[^\>]*?>(.*?)</ *script *>', re.IGNORECASE | re.DOTALL)

_script_src_re = re.compile('< *script[^>]*?src="(.*?)">[^<]*?</ *script *>', re.IGNORECASE | re.DOTALL)
