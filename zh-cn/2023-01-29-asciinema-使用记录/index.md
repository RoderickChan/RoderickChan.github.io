# asciinema 使用记录


> 简易记录`asciinema`工具录制命令行操作的使用教程。

<!--more-->

有时候需要分享命令行操作的全过程，[asciinema](https://github.com/asciinema/asciinema)是一个很好用的工具，开源免费，配合`tmux`使用直接起飞。

我使用该工具录制了`pwncli`的使用教程。

[asciinema](https://github.com/asciinema/asciinema)会将屏幕上的所有信息保存下载，生成一个`cast`后缀的文件，并且其还提供了一个工具将`cast`文件转化为`gif`。

想掌握全部的使用技巧，点击其官方网站[asciinema/asciinema: Terminal session recorder 📹 (github.com)](https://github.com/asciinema/asciinema)阅读`readme`文件即可。



# 1-安装

在`ubuntu`上安装的方式有两种：

```bash
sudo apt install asciinema
pipx install asciinema
```

# 2-录制

```shell
asciinema rec -t "title" cast_file_path
```



# 3-播放

```shell
asciinema play cast_file_path
```



# 4-上传

首先可以登录[asciinema - Record and share your terminal sessions, the simple way](https://asciinema.org/)这个网站。

然后：

```shell
asciinema auth
```

会生成一个链接，点击一下。

接下来：

```shell
asciinema upload cast_file_path
```

即可上传。

上传成功后会有一个链接，点击链接即可访问。然后可以修改标题和描述，并将录制的内容公开。

![image-20230129162457420](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230129162457420.png)



# 5-搭配tmux

搭配`tmux`可以录制分屏操作，在多个窗口之间切换。步骤如下：

- 首先，`tmux new-s -t xxx`新建一个会话
- 然后，`asciinema rec -c "tmux a -t xxx"`进行录制
- 录制结束后，要`detach`会话，接着按`Ctrl+C`即可就结束录制



# 6-转为gif

有时候想把过程放在`PPT`或者网页上，可以使用[asciinema/agg: asciinema gif generator (github.com)](https://github.com/asciinema/agg)工具将其转化为`gif`。程序使用`rust`编写，速度很快。


---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2023-01-29-asciinema-%E4%BD%BF%E7%94%A8%E8%AE%B0%E5%BD%95/  

