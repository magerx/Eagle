/*
 *  File:       EvalJS.js
 *  Author:     magerx@paxmac.org
 *  Modify:     2016-03-19
 *
 *  利用phantomjs发起请求，得到返回的页面并且处理了JS
 *  Cookie、网络请求、POST/GET
 */

var system = require("system");

var URL = null;
var cookie_path = null;
if (system.args.length > 2) {
    URL = system.args[1];
    cookie_path = system.args[2] + '/cookie.for.phantomjs.txt';
} else {
    console.log("Usage: phantomjs [options] eval_path url cookie_path");
    phantom.exit();
}

// 读取存下来的cookie和domain
var fs = require('fs');
var cookie = fs.read(cookie_path);

//var cookie = readTextFile(cookie_path);

var cookie_list = cookie.split(';');
var domain = cookie_list[0];
var code = 0;

// 主要的发送数据的逻辑
var EvalJS = function(url, cookie_list, callbackFinal) {
    var page, retrieve, webpage;
    webpage = require("webpage");
    page = null;
    retrieve = function() {
        page = webpage.create();
        page.settings.userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.89 Safari/537.36';

        // 添加cookie
        for (var i = cookie_list.length - 1; i >= 1; i--) {
            var temp = cookie_list[i].split('=');
            var name = temp[0];
            var value = temp[1];
            page.addCookie({
                'name'  : name,
                'value' : value,
                'domain': domain
            });
        };

        // 请求包的hook，中间要把css的请求干掉,不加载css减少加载时间
        page.onResourceRequested = function(request) {
            var requestData = JSON.parse(JSON.stringify(request, undefined, 4))
            if ((/http:\/\/.+?\.css/gi).test(requestData['url']) || requestData.headers['Content-Type'] == 'text/css') {
                // console.log('The url of the request is matching. Aborting: ' + requestData['url']);
                request.abort();
            }
            console.log('<a href=\'' + requestData['url'] + '\'>FROM_REQUEST</a>');
        };

        // 收到的包的hook，其中第一个是这个URL的返回包，包含状态码，打印在页面中
        page.onResourceReceived = function(response) {
            if (code == 0) {
                console.log('<hehe code=\'' + response.status + '\'>FROM_RESPONSE</hehe>');
                code = 1;
            }
        };

        // POST头上有个P，GET是G
        // 分析清楚了用哪种来发包
        var t = url[0];
        url = url.substr(1);
        if (t == 'P') {
            urlpattern = url.split('?');
            para = urlpattern[1];//url.substr(url.indexOf('?') + 1)
            url = urlpattern[0];//url.substr(0, url.indexOf('?'))
            return page.open(url, 'post', para, function(status) {
                if (status === "success") {
                    return window.setTimeout((function() {
                        console.log(page.content);
                        return callbackFinal();
                    }), 500);
                } else {
                    return callbackFinal();
                }
            });
        }
        else {
            return page.open(url, function(status) {
                if (status === "success") {
                    return window.setTimeout((function() {
                        console.log(page.content);
                        return callbackFinal();
                    }), 500);
                } else {
                    return callbackFinal();
                }
            });
        }
    };
    return retrieve();
};

try{
   EvalJS(URL, cookie_list, function() {
    return phantom.exit();
});

}
catch (err){
    console.log(err.message);
    phantom.exit();
}

