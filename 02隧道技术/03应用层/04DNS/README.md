### 案例5-应用层DNS隧道配合CS上线-检测,利用，说明
```
当常见协议监听器被拦截时，可以换其他协议上线，其中dns协议上线基本通杀
1.云主机Teamserver配置端口53启用-udp
2.买一个域名修改解析记录如下：
A记录->cs主机名->CS服务器IP
NS记录->ns1主机名->上个A记录地址
NS记录->ns2主机名->上个A记录地址
3.配置DNS监听器内容如下：
ns1.xiaodi8.com
ns2.xiaodi8.com
cs.xiaodi8.com
```