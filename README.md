# fastjsondnslog
Burp 插件

用dnslog来进行探测，使用到的payload为：{"@type":"java.net.Inet4Address","val":"x.dnslog.cn"}   (全版本支持 fastjson <= 1.2.72)

![Image text](https://github.com/f0ng/fastjsondnslog/blob/master/1.png)

马赛克处为靶机host
1.可以看到哪个域名的，当请求数量多了，网络延迟，会造成A请求与B请求混淆，这样在请求的dnslog加上host可以起到唯一标识作用
2.可以看到请求的方法、路径
3.识别Content-Type类型为json才会发送请求，并不是所有请求都会发送该请求，且做到了三个请求探测
