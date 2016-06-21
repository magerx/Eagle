# -*- encoding:utf-8 -*-

"""
File:       dic.py
Author:     magerx@paxmac.org
"""

"""
主要记录信息泄露扫描的一些payload
"""

BASHRC = "/.bashrc"
BASH_HISTORY = "/.bash_history"
BUILD = "/build.sh"
TEST_CGI = "/cgi-bin/test-cgi"
CROSSDOMAIN = "/crossdomain.xml"
DS_Store = "/.DS_Store"
GIT = "/.git/config"
HATCCESS = "/.htaccess"
PCHECK = "/pcheck/index.php"
PHPMYADMIN = "/phpmyadmin/ChangeLog"
SVN = "/.svn/entries"
PHPINFO = "/phpinfo.php"
ELASTICSEARCH = ":9200/_cat/indices"
MONGODB = ":27017/test/"
HADOOP = "/dfshealth.html"
SOLR = ":8983/solr/#/"

#dict key是payload,value是特征
pathlist = {
            BASHRC: 'Source global definitions',
            BASH_HISTORY: 'cd..\n',
            BUILD: '#! /bin/sh',
            TEST_CGI: 'SERVER_SOFTWARE',
            CROSSDOMAIN: 'allow-access-from domain="*"',
            DS_Store: 'Bud1',
            GIT: 'repositoryformatversion',
            HATCCESS: 'RewriteEngine',
            PCHECK: 'Welcome Pcheck!',
            PHPMYADMIN: 'phpMyAdmin - ChangeLog',
            SVN: 'dir\n',
            ELASTICSEARCH: '_river',
            MONGODB: 'You are trying to access MongoDB',
            HADOOP: 'Datanode Information',
            SOLR: 'Solr Admin',
        }