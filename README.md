# fastjsondnslog
#### Burp 插件 探测fastjson

用dnslog来进行探测，使用到的payload为：{"@type":"java.net.Inet4Address","val":"x.dnslog.cn"}   (全版本支持 fastjson <= 1.2.72)

![Image text](https://github.com/f0ng/fastjsondnslog/blob/master/1.png)

#### 马赛克处为靶机host
### 1.可以看到哪个域名的，当请求数量多了，网络延迟，会造成A请求与B请求混淆，这样在请求的dnslog加上host可以起到唯一标识作用
### 2.可以看到请求的方法、路径
### 3.识别Content-Type类型为json才会发送请求，并不是所有请求都会发送该请求，且做到了三个请求探测

# fastjsondnslog
#### Burp 插件 探测fastjson反序列化漏洞

用dnslog来进行探测是否有fastjson反序列化漏洞，所以需要和dnslog相通

### 1.可以看到哪个域名的，当请求数量多了，网络延迟，会造成A请求与B请求混淆，这样在请求的dnslog加上host可以起到唯一标识作用
### 2.可以看到请求的方法、路径，方便查找
### 3.~~识别Content-Type类型为json才会发送请求，并不是所有请求都会发送该请求，且做到了三个请求探测~~ 发现一些站点，如国内几个src，把json请求放在get里面的，这样就探测不到了，所以进行了改进，可以识别出来get请求里的{}格式，包括url编码的，亲测用本工具挖过两家src fastjson rce，5000R左右
### 4.不会冗余，做到请求去重，单个请求只会探测一次，其他burp的fastjson工具可能看到请求都会去探测

# todo
高版本的payload没有加进来
