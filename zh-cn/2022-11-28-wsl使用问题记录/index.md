# WSL使用问题记录


>  记录一下使用`wsl2`的时候遇到的问题和解决方案。

<!--more-->

# 1 更新内核头文件和支持编译ko

复现`CVE`的时候发现`io_uring.h`缺失一些宏定义。

参考[WSL升级到最新版本Linux内核headers的方法 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/557839637)。不要在`/mnt`目录下编译。

步骤如下：

1. 使用`uname -r`查看当前内核的版本
2. 到[Releases · microsoft/WSL2-Linux-Kernel (github.com)](https://github.com/microsoft/WSL2-Linux-Kernel/releases)下载对应版本的源码
3. 解压缩源码`tar -zxvf xxxx.tar.gz`
4. 进入源码文件夹，拷贝配置文件`cp Microsoft/config-wsl .config`
5. 安装所需依赖`sudo apt install libelf-dev build-essential pkg-config bison build-essential flex libssl-dev libelf-dev bc dwarves`
6. 执行命令`make oldconfig && make prepare && make scripts && sudo make modules && sudo make modules_install && make headers_install && sudo cp -r ./usr/include/*  /usr/include`

之后编译`ko`更改一下`include path`即可。

如果想编译任意版本的`linux ko`，需要四步：

1. 下载对应版本源码
2. 编译`bzImage`
3. `make modules`
4. 更改`Makefile`中的表示`kernel include dir`的这个变量即可



# 2 wsl中的runlevel问题

安装一些软件包的时候，会报出一些关于`runlevel`的错误，这个时候：

```bash
export RUNLEVEL=1
sudo apt install --reinstall xxxx
```



# 3 WSL2中安装kali，使用apt install报错

如图所示解决即可：

![image-20221128163110588](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20221128163110588.png)



# 4 WSL 中挂载windows磁盘的权限问题

有时候需要控制`/mnt/x/`的权限，需要在对应的操作系统中，新建一个文件`/etc/wsl.conf`。输入以下内容：

```ini
[automount]
uid=1000
gid=1000
umask=022
```

之后就能看到宿主机磁盘文件的权限，属主变成了`1000`的用户。

主要是为了解决直接从`linux`系统中访问`windows`磁盘文件的权限问题。

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-11-28-wsl%E4%BD%BF%E7%94%A8%E9%97%AE%E9%A2%98%E8%AE%B0%E5%BD%95/  

