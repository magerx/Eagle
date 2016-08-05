# -*- encoding:utf-8 -*-

"""
File:       Gziphandle.py
Author:     magerx@paxmac.org
"""

import urllib2
import zlib
from gzip import GzipFile
from StringIO import StringIO


class ContentEncodingProcessor(urllib2.BaseHandler):
    """
    A handler to add gzip capabilities to urllib2 requests
    """

    # add headers to requests
    def http_request(self, req):
        req.add_header("Accept-Encoding", "gzip, deflate")
        return req

    # decode
    def http_response(self, req, resp):
        old_resp = resp
        # gzip
        if resp.headers.get("content-encoding") == "gzip":
            gz = GzipFile(
                fileobj=StringIO(resp.read()),
                mode="r"
            )
            resp = urllib2.addinfourl(gz, old_resp.headers, old_resp.url, old_resp.code)
            resp.msg = old_resp.msg
        # deflate
        if resp.headers.get("content-encoding") == "deflate":
            gz = StringIO(self.deflate(resp.read()))
            resp = urllib2.addinfourl(gz, old_resp.headers, old_resp.url, old_resp.code)  # 'class to add info() and
            resp.msg = old_resp.msg
        return resp

    def deflate(self, data):  # zlib only provides the zlib compress format, not the deflate format;
        try:  # so on top of all there's this workaround:
            return zlib.decompress(data, -zlib.MAX_WBITS)
        except zlib.error:
            return zlib.decompress(data)
