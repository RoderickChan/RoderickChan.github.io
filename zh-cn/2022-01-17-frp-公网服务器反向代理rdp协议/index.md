# frp + rdp 实现跨局域网远程桌面控制


> 利用`frp`工具和`rdp`协议，借助公网`IP`自己搭建一个远程桌面服务，用于代替向日葵和`teamview`等软件。


<!--more-->



## 前言

严格来说，本篇博客不算是教程，只是之前折腾`frp`这款工具的一个记录，即如何利用`frp`这款强大的代理软件和一个公网服务器实现内网`rdp`协议穿透，进而可以远程访问在内网中的`Windows`主机。`Windows`自带的远程桌面比其他远程软件如`Teamview`、花生壳等体验都要好很多，在拥有大带宽的网络环境时，可以做到延时低，操作流畅。

自己有个笔记本，家里放了一个台式，有时候带笔记本外出的时候有访问台式机的需求。刚开始自己也是用一些免费的远程控制软件，但是用到后期基本需要付费。前段时间趁着阿里云打折(一直在打折)的时候买了一个`ECS`云服务器，于是万事俱备，只需要借助`frp`手动搭建一下服务即可。

本篇教程的前提：

- 拥有一个公网`IP`服务器，最好是静态`IP`
- 系统至少需要为`Windows`专业版，或者想办法开启了远程桌面服务

本教程要做的事情：

- 有一个电脑`A`，处于内网；有另一个电脑`B`，也处于内网；`A`和`B`均可以访问外网；有一台公网服务器`C`。
- 在`C`上部署`frp`服务端
- 在`A`和`B`上部署`frp`客户端
- 最后实现`A`远程桌面访问`B`或者`B`远程访问`A`


## frp和rdp

这里的介绍不会太多，只是简单提一下。

关于`frp`详细的介绍可以参考[官网](https://github.com/fatedier/frp)，实在搞不懂的地方也可以翻翻源码。这款软件简洁而强大，封装性很好，使用起来非常方便。这类代理软件都是一种类似中介的角色，可以转发流量，并且在转发的过程中添加一些鉴权、认证等工作，`frp`支持的协议（模式）很多，有`tcp/udp/http`，还支持`tls`加密，点对点穿透等。需要注意的是，使用软件过程中一定注意**不要违法**！尤其需要注意，通过`IP`地址对外提供网站服务是需要备案的！

`rdp`是远程桌面协议，用于远程桌面接入，关于协议的详情可以自行搜索，这里主要关注其在`windows`上的监听的端口号为`3389`。

## 搭建过程

### 云服务器

主要涉及到云服务器的购买，`ssh`设置等。

- 可以上阿里云、腾讯云等购买一台云服务器，使用固定`IP`，资金充足的情况下，带宽越大越好。我买的是阿里云，相对来收较为便宜~

- 获取到`ECS`实例后，首先使用`root`登录到服务器上，修改好密码，创建一个普通用户，配置好`sudo`之类的。最后，修改`sshd`的配置文件，主要修改项为：

  - 禁止`root`登录
  - 禁止密码登录
  - 使用公私钥认证
  - 上传自己的公钥到服务器

- 到云服务器控制台开启相关端口。阿里云的控制台是：

  ![image-20220119200317643](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220119200317643.png)

  如需要开启`frps`运行的绑定端口、看板端口、公网服务器暴露出去的`remote port`等。


### 服务端

到`frp`的官网上下载最新的`release`包，选择符合当前公网服务器架构的二进制包。我采用的是`stcp`模式，这样可以避免在服务器上暴露端口，修改`frps.ini`，配置如下：

```
[common]
bind_port = 7000
authentication_method = token
token = auth_token # 修改为自己的token
dashboard_port = 7500
dashboard_user = admin # 最好不要用这样的用户名和密码
dashboard_pwd = admin123
```

### 客户端(被远程访问)

同样需要下载`frp`二进制包，修改`frpc.ini`，配置如下：

```
[common]
server_addr = server_ip
server_port = 7000
token = auth_token # 与服务器的token保持一致

[rdp_server]
type = stcp
use_encryption = true
use_compression = true
sk = secret_key # 修改为自己的sercet key
local_ip = 127.0.0.1
local_port = 3389
```



### 客户端(远程访问)

修改`fprc.ini`，配置如下：

```
[common]
server_addr = server_ip
server_port = 7000
token = auth_token # 与服务器的token保持一致

[rdp_client]
type = stcp
role = visitor
use_encryption = true
use_compression = true
sk = secret_key # 修改为自己的sercet key
server_name = rdp_server
local_ip = 127.0.0.1
bind_port = 7001
```

最后使用`Remote Desktop`访问`127.0.0.1：7001`地址，然后填好账户名，输入密码后即可远程访问内网的主机。

### 注册为服务

如果要用`systemctl`管理`frp`服务端的话，需要建立文件`/usr/lib/systemd/system/frp.service`，然后添加服务：

```
[Unit]
Description=frp server
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/frps -c /usr/local/bin/frps.ini
KillSignal=SIGQUIT
TimeoutStopSec=5
KillMode=process
PrivateTmp=true
StandardOutput=syslog
StandardError=inherit

[Install]
WantedBy=multi-user.target
```

然后执行：`systemctl daemon-reload`重启即可。重启后，可以用`systemctl start/restart/stop/enable`等来管理服务。

如果想要要在`Windows`上开机自启动的话，可以使用[winsw](https://github.com/winsw/winsw)或者[nssm](https://nssm.cc/)，将`frp`注册为服务，然后就会开机自启动了。

以`winsw`为例，下载了二进制包后，编写`frp_rdp.xml`：

```xml
<service>
    <id>frp</id>
    <name>frp_0.38.0_windows_amd64</name>
    <description>frpc client, this computer will be visited by rdp</description>
    <executable>E:\frp_0.38.0_windows_amd64\frpc.exe</executable>
    <arguments>-c E:\frp_0.38.0_windows_amd64\frpc.ini</arguments>
    <onfailure action="restart" delay="60 sec"/>
    <onfailure action="restart" delay="120 sec"/>
    <logmode>append</logmode>
    <logpath>logs</logpath>
</service>
```

然后执行：

```powershell
winsw.exe install frp_rdp.xml
winsw.exe start frp_rdp.xml
```



## 总结

只要搭建过一次内网穿透的服务，其他协议如`ssh/http/ftp`等的搭建都大同小异。为了安全起见，建议：

- 除了`frps`的绑定端口，尽量不要在公网服务器上暴露端口，小心被扫
- 尽量使用认证、鉴权，开启`TLS`等机制保障通信安全
- 关注`frp`的最新发布包并及时更新，毕竟万一`frp`爆出个漏洞，内网的主机是存在很大风险的

## 相关链接

- [frp](https://github.com/fatedier/frp)
- [winsw](https://github.com/winsw/winsw)
- [nssm](https://nssm.cc/)
- [frp搭建教程](https://juejin.cn/post/7042486792011907086)


---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-01-17-frp-%E5%85%AC%E7%BD%91%E6%9C%8D%E5%8A%A1%E5%99%A8%E5%8F%8D%E5%90%91%E4%BB%A3%E7%90%86rdp%E5%8D%8F%E8%AE%AE/  

