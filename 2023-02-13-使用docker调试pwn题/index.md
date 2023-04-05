# 使用docker调试和部署pwn题


> 使用`docker`快速部署不同架构、不同版本的调试环境。给出`docker`环境下`pwn`题部署模板。

<!--more-->

# 0x0 前言
关于`docker`的基础概念不做过多的介绍。可以到[Docker: Accelerated, Containerized Application Development](https://www.docker.com/)官方网站上获取更多的信息。熟悉并使用`docker`的常用命令并不需要太多的时间。

在使用`docker`指令或者`docker-compose`的指令时，尽量到官方手册上查询有关指令的详情内容。

一般来说，使用`docker-compose`来运行多个容器，也可以集成编译镜像、运行实例等流程。



# 0x1 调试环境

对于不同的版本，特别是传统的`glibc`的环境，有时候使用`patchelf`改变二进制文件的`so`无法得到与远程环境一样的内存布局，并且会缺乏调试符号。而对于部署在`debian/fedora`等其他操作系统上的程序，受到的影响会更大。因此，使用`docker`搭建一个一模一样的调试环境很有必要。

目前，我针对常用的环境制作了相关镜像，并发布在https://hub.docker.com/r/roderickchan/debug_pwn_env。

![image-20230213140845522](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230213140845522.png)

每个镜像都给出了`Ubuntu`的版本、其使用的`glibc-libc.so.6`的版本和编译时间。

直接使用`docker pull roderickchan/debug_pwn_env:22.04-2.35-0ubuntu3.1-20230213`这样的命令拉取镜像即可。

拉取镜像后，运行命令如下：

```shell
docker run -it --rm -v host_path:container_path -p host_port:container_port --cap-add=SYS_PTRACE IMAGE_ID # auto update

docker run -it -rm -v host_path:container_path -p host_port:container_port --cap-add=SYS_PTRACE IMAGE_ID /bin/bash # do not update

docker run -it --rm -v host_path:container_path -p host_port:container_port --privileged IMAGE_ID # privileged enabled and auto update
```

可以映射宿主机端口和容器端口，映射文件或者目录。如果不带命令，容器会自动更新一些`pwn`相关的仓库和包，如果带上命令，就会执行指定的命令。

事实上这个镜像的`Dockerfile`如下：

```dockerfile
ARG BUILD_VERSION

FROM ubuntu:$BUILD_VERSION

WORKDIR /root

COPY ./gdb-gef /bin
COPY ./gdb-pwndbg /bin
COPY ./update.sh /bin
COPY ./.tmux.conf ./
COPY ./.gdbinit ./
COPY ./flag /

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
RUN apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y --fix-missing python3 python3-pip python3-dev lib32z1 \
    xinetd curl gcc gdb gdbserver g++ git libssl-dev libffi-dev build-essential tmux \
    vim netcat iputils-ping cpio gdb-multiarch \
    file net-tools 

RUN apt-get -y install socat ruby ruby-dev locales autoconf automake libtool make && \
    gem install one_gadget && \
    gem install seccomp-tools && \
    sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN chmod +x /bin/gdb-gef /bin/gdb-pwndbg /bin/update.sh && \
    echo "root:root" | chpasswd && \
    python3 -m pip install --upgrade pip && \
    pip3 install ropper capstone z3-solver qiling lief libnum pycryptodome


ARG HUB_DOMAIN=github.com


RUN git clone https://${HUB_DOMAIN}/pwndbg/pwndbg && \
    cd ./pwndbg && \
    ./setup.sh

RUN git clone https://${HUB_DOMAIN}/hugsy/gef.git && \
    git clone https://${HUB_DOMAIN}/RoderickChan/Pwngdb.git

RUN git clone https://${HUB_DOMAIN}/Gallopsled/pwntools && \
    pip3 install --upgrade --editable ./pwntools && \
    git clone https://${HUB_DOMAIN}/RoderickChan/pwncli.git && \
    pip3 install --upgrade --editable ./pwncli

RUN git clone https://${HUB_DOMAIN}/NixOS/patchelf.git && \
    cd ./patchelf && \
    ./bootstrap.sh && \
    ./configure && \
    make && \
    make install

# normal user:roderick
RUN useradd roderick -d /home/roderick -m -s /bin/bash -u 1000
COPY ./.tmux.conf /home/roderick
COPY ./.gdbinit /home/roderick
RUN chown -R roderick:roderick /home/roderick

USER roderick:roderick
WORKDIR /home/roderick

RUN git clone https://${HUB_DOMAIN}/pwndbg/pwndbg && \
    git clone https://${HUB_DOMAIN}/hugsy/gef.git && \
    git clone https://${HUB_DOMAIN}/RoderickChan/Pwngdb.git && \
    git clone https://${HUB_DOMAIN}/Gallopsled/pwntools && \
    pip3 install --upgrade --editable ./pwntools && \
    git clone https://${HUB_DOMAIN}/RoderickChan/pwncli.git && \
    pip3 install --upgrade --editable ./pwncli


# expose some ports
EXPOSE 22 23946 10001 10002

CMD ["/bin/update.sh"]
```

内置了自使用的`tmux`配置文件和`gdb-gef/peda/pwndbg`三个脚本以及最新的`pwncli`库。完整文件位于[CVE-ANALYZE/basic_image at main · RoderickChan/CVE-ANALYZE (github.com)](https://github.com/RoderickChan/CVE-ANALYZE/tree/main/basic_image)，可根据需求更改和自定义配置文件。



如果是`debian`系统，只需要安装一些基础的包即可：

```shell
#!/bin/bash

set -ex

apt update && apt install -y tmux gdb gdbserver wget rpm file binutils socat python3 python3-pip procps

# 修改tmux配置
cat > ~/.tmux.conf << "EOF"
set -g prefix C-a #
unbind C-b # C-b即Ctrl+b键，unbind意味着解除绑定
bind C-a send-prefix # 绑定Ctrl+a为新的指令前缀

# 从tmux v1.6版起，支持设置第二个指令前缀
set-option -g prefix2 ` # 设置一个不常用的`键作为指令前缀，按键更快些
#set-option -g mouse on # 开启鼠标支持
# 修改分屏快捷键
unbind '"'
bind - splitw -v -c '#{pane_current_path}' # 垂直方向新增面板，默认进入当前目录
unbind %
bind | splitw -h -c '#{pane_current_path}' # 水平方向新增面板，默认进入当前目录

# 设置面板大小调整快捷键
bind j resize-pane -D 10
bind k resize-pane -U 10
bind h resize-pane -L 10
bind l resize-pane -R 10
EOF

# 安装pwntools和pwncli
pip3 install pwntools pwncli 
bash -c "$(wget https://gef.blah.cat/sh -O -)"
```

这里选用`gef`插件，因为`gef`插件的依赖少，安装速度快，功能比`peda`强大。



如果是`fedora`系统，安装软件包列表如下：

```shell
#!/bin/bash

dnf install -y tmux gdb gdb-gdbserver wget which file binutils socat python3 python3-pip procps

cat > ~/.tmux.conf << "EOF"
set -g prefix C-a #
unbind C-b # C-b即Ctrl+b键，unbind意味着解除绑定
bind C-a send-prefix # 绑定Ctrl+a为新的指令前缀

# 从tmux v1.6版起，支持设置第二个指令前缀
set-option -g prefix2 ` # 设置一个不常用的`键作为指令前缀，按键更快些
#set-option -g mouse on # 开启鼠标支持
# 修改分屏快捷键
unbind '"'
bind - splitw -v -c '#{pane_current_path}' # 垂直方向新增面板，默认进入当前目录
unbind %
bind | splitw -h -c '#{pane_current_path}' # 水平方向新增面板，默认进入当前目录

# 设置面板大小调整快捷键
bind j resize-pane -D 10
bind k resize-pane -U 10
bind h resize-pane -L 10
bind l resize-pane -R 10
EOF

pip3 install pwntools pwncli 
bash -c "$(wget https://gef.blah.cat/sh -O -)"
```

和上面基本是一样的，不过有些包的名字不一样。



# 0x2 出题模板

出题模板可以参考[RoderickChan/deploy_pwn_template: Templates for deploying pwn challenge in ctf (github.com)](https://github.com/RoderickChan/deploy_pwn_template)。

![image-20230213142229383](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230213142229383.png)

这里列出了`11`中出题模板文件，只需要按照不同的模板文件把二进制文件替换一下，设置`flag`等操作即可。

不同的模板各有优缺点。大部分的模板都支持从环境变量中动态获取`flag`和设置`sha256`的`proof of work`。

- 如果想要编译后体积小的镜像，优先采用`alpine`系列模板，不过要结合`patchelf`来部署`glibc`的题。
- 如果想限制系统调用，可以使用`kctf+nsjail`或者`red.pwn.jail`
- 如果想限制运行目录，可以采用`ubuntu+xinetd+chroot`
- ......

总有一款适合你。

以`ubuntu+xinetd+chroot`为例，把题目源码放置在`src`目录下，修改编译文件和`Dockerfile`中的编译环境。

如果需要动态`flag`，就把`docker-compose.yaml`的`FLAG`环境变量设置为真正的`flag`，如果不需要，删除`FLAG`环境变量即可。

如果需要`pow`，就把`docker-compose.yaml`的`ENABLE_POW`环境变量设置为`1`，否则设置为`0`或者删除均可。

如下图，使用`pow`时会验证`sha256`，可有效地避免爆破。

![image-20230213143720336](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230213143720336.png)

# 0x3 使用技巧

这里给出一些我使用`docker`的调试技巧。

1. 使用`docker commit`将容器保存为镜像
2. 使用`docker save/load`保存和传输体积较小的镜像
3. 使用`docker cp xxx:/lib/libc.so.6 .`拷贝环境使用的`libc.so.6`
4. 运行容器的时候至少映射一个端口，以备不时之需
5. 有些调试环境只需要安装一个`gdbserver`即可，然后启动容器的时候映射一下端口，在宿主机上使用`gdb file -ex 'target remote 127.0.0.1:port'`挂上去调试。这样既可以保证环境和远程一样，又能够使用本地的编辑器、文件，还不需要为镜像安装太多的软件包。
6. 碰到需要输入特殊字符的场景，可以把所有给程序的输入保存到一个文件里面，然后使用`gdb ./pwn < input`启动，这个时候最好关闭`aslr`，避免地址空间不一样。
7. 有时候忘记了映射端口，可以参考[docker修改、增加和删除已创建容器映射端口 - orcl - 博客园 (cnblogs.com)](https://www.cnblogs.com/orcl-2018/p/15450219.html)，按步骤进行就好。
8. 有时候忘记了映射目录，可以自己写一个`python`脚本，检查相关文件是否改动，如果改动，就执行`docker cp`命令拷贝。
9. 使用有名管道等通信文件和`tmux`，甚至可以把容器和本地调试环境无缝衔接。具体的做法就是：容器和宿主机映射同一个有名管道文件；容器内使用`gdbserver :1234 ./pwn < pipe`启动；宿主机`gdb`远程链接，然后往管道文件写内容进行交互。如果同时想用脚本去调试，可以将第二步改为：`./pwn > pipe1 < pipe2`，然后宿主机读`pipe1`获取输出，写`pipe2`给程序输入。



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/2023-02-13-%E4%BD%BF%E7%94%A8docker%E8%B0%83%E8%AF%95pwn%E9%A2%98/  

