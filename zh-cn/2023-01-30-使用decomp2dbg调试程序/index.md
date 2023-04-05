# 使用decomp2dbg调试程序


> 使用`decomp2dbg`工具，统筹使用`IDA`和`gdb`调试程序。截至到目前(`2022-02-07`)，测试出工具的缺陷在于：函数较多时，会陷入卡顿状态；打开`vmlinux`，插件启动报错。

<!--more-->

`IDA`和`gdb`的交互，很多`gdb`的插件都实现了一些，但是实现得最好的，还得是[mahaloz/decomp2dbg: A plugin to introduce interactive symbols into your debugger from your decompiler (github.com)](https://github.com/mahaloz/decomp2dbg)。这个项目很早之前就关注了，但是最开始其主要是基于`pwndbg`和`gef`实现的二次开发。

今天又逛到了这个仓，发现作者重新实现了一遍，不再依赖这两个插件，使得原生的`gdb`也能直接使用。目前，工具已经实现了很多实用的功能，因此，本篇博客简要记录一下该工具的使用步骤。



# 1-安装

对于`windows`上使用`IDA`的场景，选择手动安装会更好。苹果可以选择自动安装。手动安装的步骤如下：

首先，去官网`clone`仓库，拷贝`decompilers/d2d_ida/*`到`IDA/plugins`目录下面。

然后，在`linux`系统（`WSL`或者虚拟机均可）里面执行：

```bash
pip3 install . && \
cp d2d.py ~/.d2d.py && echo "source ~/.d2d.py" >> ~/.gdbinit
```

最后，在`windows`机器的防火墙中添加一个入站规则，选择端口为`tcp/3662`，只对私有域放行端口。



# 2-使用

第一步，使用`IDA`打开一个程序，然后在`edit/plugins`中选择`Decomp2DBG`，选择监听`0.0.0.0`和`3662`端口。

第二步，使用`gdb`调试同一个程序，启动之后，直接键入`decompiler connect ida --host 192.168.xxx.xxx(LAN IP) --port 3662`。就可以同步更新`IDA`的反编译代码了。

![decomp2dbg](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/decomp2dbg.png)

之后在`IDA`重命名了函数或者变量，也会在`gdb`中更新，并可以直接打印。还支持打印结构体，同步栈变量，断点等等，功能非常强大。

![image-20230130211113068](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230130211113068.png)

这样在gdb调试的时候，就知道程序运行到哪个函数了。



使用`pwncli`的话，可以使用命令`pwncli de ./pwn -t -s "decompiler connect ida --host 192.168.xxx.xxx --port 3662" -b func`，这个时候，`func`可以指定为`IDA`中重命名的函数，示例如下。

`IDA`里面是这样的：

![image-20230130214342462](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230130214342462.png)

以下为操作示例。

![8f5d53fe-08fd-4f15-9619-d7952f8d5b6d](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/8f5d53fe-08fd-4f15-9619-d7952f8d5b6d.gif)



目前该工具已经支持调试`so`，其开发的功能概览如下：

![image-20230130205331909](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230130205331909.png)

总的来看，这个工具适合调试一些虚拟机或者分支很多的程序，或者结构体很复杂的程序。期待新的功能~



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2023-01-30-%E4%BD%BF%E7%94%A8decomp2dbg%E8%B0%83%E8%AF%95%E7%A8%8B%E5%BA%8F/  

