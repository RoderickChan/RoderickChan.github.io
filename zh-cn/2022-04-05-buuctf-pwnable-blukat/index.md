# buuctf-pwnable_blukat



### 总结

直接把远程的源码和`password`下载下来然后修改一下逻辑即可获得`flag`。

<!-- more -->

### EXP

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
char flag[100];
char password[100];
char* key = "3\rG[S/%\x1c\x1d#0?\rIS\x0f\x1c\x1d\x18;,4\x1b\x00\x1bp;5\x0b\x1b\x08\x45+";
void calc_flag(char* s){
        int i;
        for(i=0; i<strlen(s); i++){
                flag[i] = s[i] ^ key[i];
        }
        printf("%s\n", flag);
}
int main(){
        FILE* fp = fopen("./password", "r");
        fgets(password, 100, fp);
        char buf[100];
        printf("guess the password!\n");
        fgets(buf, 128, stdin);
        if(strcmp(password, buf)){ // 这里改一下即可
                printf("congrats! here is your flag: ");
                calc_flag(password);
        }
        else{
                printf("wrong guess!\n");
                exit(0);
        }
        return 0;
}
```

![image-20220405154534330](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220405154534330.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2022-04-05-buuctf-pwnable-blukat/  

