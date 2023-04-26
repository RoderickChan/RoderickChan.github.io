# socat反弹shell+tmux共享会话


> 使用`socat`得到一个带有`pty`的`strong shell`，然后使用`tmux`共享会话和结对编程。

<!--more-->

# socat反弹shell

反弹`shell`的原理并不复杂，需要建议的一点是，若是`A`弹`shell`给`B`，那么最好是`B`拥有公网`IP`，否则由`A`把程序和公网`IP`的端口绑定的话，任何人都能通过该端口访问到反弹的`shell`。

使用`nc`或者`bash -i > /dev/tcp/xxxx`等的方式反弹的`shell`是没有`tty`的，那么使用<kbd>Ctrl</kbd>+<kbd>C</kbd>会退出程序，而不是给`tty`发送信号。同时，无法使用`tmux`分屏复用工具，无法使用自动补全功能等。

如果想要像`ssh`会话一样使用`shell`，就需要反弹一个带有`tty`的`shell`，可以借助`socat`来实现这一功能。

## 你弹给我

我有公网`IP`，地址为：`1.1.1.1`

我在`1.1.1.1`机器上执行：

```shell
socat file:`tty`,raw,echo=0 tcp-listen:9999,bind=0.0.0.0,reuseaddr,fork
```

你在自己的机器上执行：

```shell
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:1.1.1.1:9999
```

如果有`zsh`，反弹一个`zsh`也不错。

还可以把弹`shell`的操作，换成给一个容器`docker run -it xxx /bin/sh`，或者其他需要借助`tty`的操作。

## 我弹给你

- 假如你有公网`IP`，把上面的流程反过来即可。
- 假如你没有公网`IP`，那么可以执行下面的操作。**注意**：下面的操作比较危险，不建议在公网上尝试。



我有公网`IP`，地址为：`1.1.1.1`

我在`1.1.1.1`机器上执行：

```shell
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp-listen:9999,bind=0.0.0.0,reuseaddr,fork
```

你在自己的机器上执行：

```shell
socat file:`tty`,raw,echo=0 tcp:1.1.1.1:9999
```



同时，还可以借助`frp`这样的反向代理工具，将公网`IP`当做跳板，把处于局域网机器的`shell`分享出去。



# tmux共享会话

`tmux`是一款终端复用工具，非常好用，极力推荐~

## 组会话

新建一个公共会话，命名为`groupSession`。

```shell
tmux new -s groupSession
```

其他用户先**登陆同一个账号**，但不去直接连接这个会话，而是通过创建一个新的会话来加入上面的公共会话`groupSession`。

```shell
tmux new -t groupSession -s otherSession
```

此时两个用户都可以在同一个会话里操作，就会好像第二个用户连接到了`groupSession`的会话一样。此时两个用户都可以创建新建的窗口，新窗口的内容依然会实时同步，但是其中一个用户切换到其它窗口，对另外一个用户没有任何影响，因此在这个共享的组会话中，用户各自的操作可以通过新建窗口来执行。即使第二个用户关闭`otherSession`会话，共享会话`groupSession`依然存在。

组会话在共享的同时，又保留了相对的独立，非常适合结对编程场景，它是结对编程最简单的方式。

**优点**：

- 会话完全共享
- 既可以共享回话，又能保持相对独立。

**缺点**：

- 账号必须共享
- 组会话所需的权限会带来安全隐患



因此，建议只和比较熟悉的人一起使用组会话功能。



演示视频如下：

{{< bilibili BV1js4y1e7tu >}}

## socket共享

第一个用户指定一个`socket`文件来创建`tmux session`

```shell
tmux -S /tmp/shared new-session -s shared
```

另一个用户通过这个`socket`文件来`attach`上会话，需要保证有相关权限，否则会因权限不足而报错。

```
# 可读可写
tmux -S /tmp/shared attach-session -t shared

# 只读
tmux -S /tmp/shared attach-session -t shared -r
```

**优点**：

- 会话完全共享
- 不需要使用同一个账户
- 只需要控制创建的`socket`文件的权限即可



**缺点**：

- 之后加入的用户无法使用自己的配置文件
- 共享时无法创建独立窗口，所有人的会话都是完全一样的



演示视频如下：

{{< bilibili BV17D4y1P7yz >}}



# 合并使用

## 使用场景

什么时候需要使用`socat`反弹`shell`+`tmux`共享会话的操作呢？有下面这几种场景可以使用：

1. 想和小伙伴一起分享终端上的操作，但是又不想给`ssh`账号，或者说不想把`ssh`暴露在公网上
1. 不想用腾讯会议这样的软件进行共享（腾讯会议能看到的东西太多了）
2. 想给对方分享如何调试程序，需要一个人操作，一个人看，比如一起打`CTF`
3. 想帮对方安装软件
3. 协调解决服务器上的问题
4. 想和小伙伴一起在终端工作，同时又能知道对方的操作，比如一起打`CTF`
5. ······



如果想既要一起操作，又可以相对独立操作各自的窗口，那么就应该使用上面所提到的**组会话**功能。但之前提到了，组会话需要共享一个账号，也就是共享`ssh`的账户密码或者反弹一个自己的`shell`过去，如果双方并不熟悉，某一方要干坏事（比如种个马）的话，这种方式就会显得很不安全。因此，建议使用`socket`共享会话功能。下面所提到的都是`socket`共享回话的操作。



## 分享你的

**原则**依旧是：`A`给`B`分享，`B`要有一个公网`IP`服务器。



我有公网`IP`，地址为：`1.1.1.1`

我在`1.1.1.1`机器上执行：

```shell
# 监听9999端口
socat file:`tty`,raw,echo=0 tcp-listen:9999,bind=0.0.0.0,reuseaddr,fork
```

你在自己的机器上执行：

```shell
# 打开两个终端窗口，第一个终端执行分割线之上的命令
# 创建会话
tmux -S /tmp/shared new-session -s shared
#-------------------------------------------------
# 第二个终端执行下面的命令
# 修改socket文件的权限
chmod o+rw /tmp/shared
# 添加临时用户
sudo useradd tmpuser
# 切换到临时用户并分享会话
sudo su -c "socat exec:'tmux -S /tmp/shared attach-session -t shared',pty,stderr,setsid,sigint,sane tcp:1.1.1.1:9999" tmpuser
# 删除临时用户
sudo userdel tmpuser
# 删除socket文件
/bin/rm /tmp/shared
```

## 分享我的

与上面反弹`shell`类似。



- 假如你有公网`IP`，把上面的流程反过来即可。
- 假如你没有公网`IP`，那么可以执行下面的操作。**注意**：下面的操作比较危险，不建议在公网上尝试。



我有公网`IP`，地址为：`1.1.1.1`

我在`1.1.1.1`机器上执行：

```shell
# 打开两个终端窗口，第一个终端执行分割线之上的命令
# 创建会话
tmux -S /tmp/shared new-session -s shared
#-------------------------------------------------
# 第二个终端执行下面的命令
# 修改socket文件的权限
chmod o+rw /tmp/shared
# 添加临时用户
sudo useradd tmpuser
# 切换到临时用户并分享会话
sudo su -c "socat exec:'tmux -S /tmp/shared attach-session -t shared',pty,stderr,setsid,sigint,sane tcp-listen:9999,bind=0.0.0.0,reuseaddr,fork" tmpuser
# 删除临时用户
sudo userdel tmpuser
# 删除socket文件
/bin/rm /tmp/shared
```

你在自己的机器上执行：

```shell
socat file:`tty`,raw,echo=0 tcp:1.1.1.1:9999
```

结束共享的时候，不要使用`tmux detach`，键入`exit`来结束。结束后记得删除`socket`文件。



## 一起操作

如果不需要独立窗口，两边读写同步的话，则使用**socket共享会话**功能。

上面的操作默认都是读写同步的。

## 我做你看

如果是你分享的会话，那么只需要把上面的`分享你的`的操作变为：

我有公网`IP`，地址为：`1.1.1.1`

我在`1.1.1.1`机器上执行：

```shell
socat file:`tty`,raw,echo=0 tcp-listen:9999,bind=0.0.0.0,reuseaddr,fork
```

你在自己的机器上执行：

```shell
# 打开两个终端窗口，第一个终端执行分割线之上的命令
# 创建会话
tmux -S /tmp/shared new-session -s shared
#-------------------------------------------------
# 第二个终端执行下面的命令
# 修改socket的权限
chmod o+rw /tmp/shared
# 添加临时用户
sudo useradd tmpuser
# 切换到临时用户并分享会话
sudo su -c "socat exec:'tmux -S /tmp/shared attach-session -t shared -r',pty,stderr,setsid,sigint,sane tcp:1.1.1.1:9999" tmpuser
# 删除临时用户
sudo userdel tmpuser
/bin/rm /tmp/shared
```

可以看到，只有一个地方不一样，就是`tmux -S /tmp/shared attach-session -t shared`再带上一个`-r`参数，使得会话只读。



## 你做我看

同样的，修改命令为`tmux -S /tmp/shared attach-session -t shared -r`即可。



演示视频如下：

{{< bilibili BV1NR4y1B7LL >}}



# 参考

1. <https://blog.csdn.net/fm18771120556/article/details/123524078>
2. <http://louiszhai.github.io/2017/09/30/tmux/#%E5%85%B1%E4%BA%AB%E8%B4%A6%E5%8F%B7-amp-%E7%BB%84%E4%BC%9A%E8%AF%9D>


---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2023-02-10-socat%E5%8F%8D%E5%BC%B9shell-tmux%E5%85%B1%E4%BA%AB%E4%BC%9A%E8%AF%9D/  

