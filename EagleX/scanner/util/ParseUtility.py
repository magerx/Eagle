# -*- encoding:utf-8 -*-

"""
File:       ParseUtility.py
Author:     magerx@paxmac.org
"""

from lxml import etree
from EagleX.scanner.util.URLUtility import url_process

"""
分析HTML页面的函数，拿到链接
"""


def form_process(form, url):
    """
    处理表单，合成URL
    :form:      xpath下的节点
    :url:       当前URL
    :return:    (url, form)非登录表单时返回None
    """
    url = (url if '?' not in url else url.split('?')[-1])

    # 分析表单里的提交项
    form = analyze_form(form)

    # 合成GET格式的URL
    temp = ""
    for x in form:
        temp += "{0}={1}&".format(x[0], x[1])
    if temp:
        temp = temp.rstrip('&')
        url = "{0}?{1}".format(url, temp)

    return url, form if is_normal_login_form(form) else None


def analyze_form(form):
    """
    分析表单拿到所有的提交项的列表
    :form:      输入表单
    :return:    [(name, value, type), ...]
    """
    f_input = []
    inputs = form.xpath('//*')  # 只要有name的都取
    for s_input in inputs:
        # 跳过没有name的选项
        if s_input.attrib.get('name') is None:
            continue

        f_input.append(
            (
                s_input.attrib.get('name'),
                s_input.attrib.get('value', ''),  # if s_input.attrib.get('value') is not None else '',
                s_input.attrib.get('type', '')  # if s_input.attrib.get('type') is not None else ''))
            )
        )
    return f_input


def is_normal_login_form(form):
    """
    判断表单是否为一般的登录表单
    :form:      [(name, value, type), ...]
    :return:    True or False
    """
    # text_c = 0
    passwd_c = 0
    for s_input in form:
        # text_c += 1 if s_input[2] == 'text' else 0
        passwd_c += 1 if s_input[2] == 'password' else 0

    # username + password or password only
    if passwd_c >= 1:
        return True
    # password only
    # if passwd_c == 1 and text_c == 0:
    #     return True
    return False


def parse_page(url, srcpage, depth):
    """
    分析页面，提取出URL
    :url:       当前URL
    :srcPage:   页面源码
    :depth:     当前页面的深度
    :return:    statusCode, urls, [(url, login_form), ...]
                                    login_form = [(name, value, type), ...]
    """
    depth += 1
    try:
        page = etree.HTML(srcpage.decode('utf-8'))
    except Exception as e:
        return 0, [], []

    # 提取当前页面的状态码
    links = page.xpath('//hehe')
    code = links[0].attrib.get('code')
    code = int(code) if code != 'null' else 0

    # 跳转的页面，换成新的URL
    # 存在有的乱七八糟的返回，302没有目标URL，这种情况不替换
    if code == 302 or code == 301:
        t = page.xpath('//a')
        if len(t) > 1:
            url = t[1].attrib.get('href')
    # 404直接返回空
    elif code == 404:
        return 404, [], []

    urls = []

    # 处理a链接，其他部分因为流量已经被hook了所以不用处理
    links = page.xpath('//a | //area | //base')
    for link in links:
        href = link.attrib.get('href')
        if href is None:
            continue

        # 专门处理mailto和javascript
        f_url = href.lstrip(' ')
        pseudo_protocol = ['mailto', 'javascript', 'data', '#']
        if f_url.split(':', 1)[0] in pseudo_protocol:
            continue

        f_url = url_process(f_url, url).rstrip(chr(0x0d))
        # self.log([f_url])
        urls.append((f_url, 0, 0, depth))

    # 处理img的src，因为关闭了phantomjs的imgload选项
    imgs = page.xpath('//img')
    for img in imgs:
        if img.attrib.get('src') is None:
            continue

        f_url = url_process(img.attrib.get('src'), url).rstrip(chr(0x0d))
        urls.append((f_url, 0, 0, depth))

    # 处理表单
    login_forms = []
    forms = page.xpath('//form')
    for form in forms:
        if form.attrib.get('action') is None:
            continue

        f_url = url_process(form.attrib.get('action'), url).rstrip(chr(0x0d))
        f_url, login_form = form_process(form, f_url)
        is_post = form.attrib.get('method')

        if is_post is None or is_post.lower() == 'post':
            is_post = 0
        else:
            is_post = 1
        urls.append((f_url, is_post, 0, depth))

        # 添加登录表单
        if login_form is not None:
            login_forms.append((f_url, login_form))

    return code, urls, login_forms
