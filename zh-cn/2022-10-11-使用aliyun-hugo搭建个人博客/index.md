# 使用aliyun+hugo搭建个人博客


整个搭建过程中，云服务器配置耗费时间需要`1~2`周，而在配置云服务器过程中占用时间最长的为域名备案，最长需要等待`2`周才能完成；剩下的几步只需要不到两个小时的时间即可完成。

<!--more-->

>  使用云服务器`VPS`和`hugo`搭建个人博客的端到端教程。本篇教程以`aliyun`服务器为例，使用`hugo`的`even`主题，并在原有主题的基础参考其`issue`和`pr`上进行了自定义修改。本教程操作主要在`windows`系统上进行，换到`linux`系统也大同小异。
>
> 本文分为`7`个章节：
>
> 0、前言
>
> 1、云服务配置
>
> 2、`hugo`使用方法
>
> 3、`even`主题配置
>
> 4、`nginx`反向代理
>
> 5、教程总结
>
> 6、引用与参考

---

# ChangeLog
## 2023-04-05更新
小小吐槽一句，国内使用域名会增加好多不必要的烦恼😅

因为某些原因，我将重新启用`roderickchan.github.io`这个域名（本来打算归档的，但是人算不如天算）。原来写的文档（基本全是些学习`pwn`的时候写的`wp`）也会保留下来（但是评论都没了）。估计又得折腾半天了😟

之后，以下两个域名提供的博客内容是一样的：
- `https://www.roderickchan.cn`
- `https://roderickchan.github.io`

域名`roderickchan.cn`可能某一天无法访问，但是`github pages`应该是永远（只要`github`不作妖）能访问的。所以，需要收藏我的文章的话~~如果有人看~~，请优先`roderickchan.github.io`。

## 2023-03-13更新

使用`algolia`来搭建`search database`，按照这个博客[使用 Algolia 云引擎，实现个人博客 Hugo 本地智能搜索_回忆中的明天的博客-CSDN博客](https://blog.csdn.net/lb52406/article/details/125564605)的教程一步一步搭建即可，`fixit`主题只需要把相关配置弄好就行。最后给出一个`python`实现的上传`index.json`模板：

```python
from algoliasearch.search_client import SearchClient
import json
# https://www.algolia.com/doc/api-client/getting-started/install/python/?client=python

def upload(appid, adminkey, indexname, jsonfilepath):
    client = SearchClient.create(appid, adminkey)
    index = client.init_index(indexname)
    # search 
    # objects = index.search('glibc')
    # print(objects)
    with open(jsonfilepath, "rb") as f:
        records = json.load(f)
    index.save_objects(records,  {'autoGenerateObjectIDIfNotExist': True})
    print(f"upload {jsonfilepath} success!")
    client.close()

if __name__ == "__main__":
    index_en = "index.en"
    json_zh_path = "./public/index.json"

    json_en_path = "./public/en/index.json"
    index_zh = "index.zh-cn"

    application_id = ""
    admin_key = ""
    upload(application_id, admin_key, index_zh, json_zh_path)
    upload(application_id, admin_key, index_en, json_en_path)
```



## 2023-02-27 更新

使用`waline`部署评论系统，参照以下文档进行操作即可：

- [Waline | Waline](https://waline.js.org/)
- [Waline 评论系统的介绍与基础配置 | 荷戟独彷徨 (guanqr.com)](https://guanqr.com/tech/website/introduction-and-basic-setting-of-waline/#)

可以免费部署，设置邮件提醒功能。

特别是邮件提醒功能，他真的，我哭死😭（想到了之前用`valine`实现邮件通知时候因为是开发版环境实例被强制休眠的痛）。

## 2023-02-26 更新

虽然`even`很好用，但是其缺乏搜索功能，并且如果使用`proxy`的话，用`lunr`搜索会失败。

所以虽然使用`hugo`的第一个博客主题是`even`，但我还是~~不舍地~~换成了`FixIt`。

虽然换了`FixIt`，但我想本文的标题还是需要包含`even`，毕竟大部分内容都与`even`有关。

考察多个主题后，最后选用了[hugo-fixit/FixIt: 🔧 A clean, elegant but advanced blog theme for Hugo 一个简洁、优雅且高效的 Hugo 主题 (github.com)](https://github.com/hugo-fixit/FixIt)。不得不说这个主题做得真的非常好~

- 可以针对某个专题进行分类
- 使用`algolia`在线搜索（虽然还要上传`index.json`，但是总算能实现搜索功能了）
- 支持`day/night`切换
- 支持很多种`shortcodes`
- ......


于是，在这个周末花了一天时间，把博客主题迁移到了`FixIt`。主要工作量是需要根据作者的模板修改自己的配置。

---



# 0 前言

我最开始搭建博客使用的解决方案为`github.io + hexo + icarus`，该方案的优点是`github.io`自带域名，不需要购买额外的域名，一次搭建成功后，往后只需要专注于写作即可。但是，其缺点也是显而易见的。

首先，`github`域名在国内访问不够方便；其次，`hexo`的部署也稍显麻烦，想要部署成功除了需要安装`nodejs`，还需要安装一大堆依赖包，其安装成本较大，安装过程繁琐，更换电脑后博客迁移步骤繁琐。

起初本来想着制作一个`docker`镜像来避免在不同电脑上的重复安装工作，然而，并不是每个电脑都支持运行`docker`，而制作镜像的事情一直拖着至今都未开始做。

使用`hugo`搭建博客的好处有：

1. `hugo`安装简单，只有一个二进制文件
2. `theme`配置简便
3. 博客迁移便捷

简单，才是最强大的。



# 1 云服务器配置

## 1.1 购买云服务器和域名

要想从世界上任何一个地方都访问到你的博客站点，你需要一个公网`IP`，云服务器可以提供一个静态的公网`IP`。当然，还有其他获取公网`IP`的办法，可自行搜索。

国内云服务器的厂商很多，我选择的是阿里云。主要是因为阿里云的服务器第一年很便宜。如果买最低的配置，第一年只需要`40`块钱左右。但是，几乎所有的云服务器都有一个共同的特点：**续费很贵**。所以要买的话，建议`3`年起买。

关于云服务器的选择，直接选最低的配置即可满足要求，一般的配置是：`1G`内存+`2`核`CPU` + `40G`系统盘。如果还想把服务器拿来穿透一些内网服务的话，建议加大带宽。根据我的经验，带宽和价格似乎并不是呈线性关系，带宽越高，价格翻倍得越离谱。

由于阿里云同时提供域名注册服务，所以我直接在阿里云上购买了域名。

## 1.2 相关配置

主要有服务器的配置和域名配置

**1、`ssh`服务配置**

系统一般自带了`ssh`服务，如果没有的话，可以自己装一个。装完之后，修改`/etc/ssh/sshd_config`文件，主要修改项为：

```bash
# 禁止root登录
PermitRootLogin no
# 使用公钥认证
PubkeyAuthentication yes
# 禁止密码认证
PasswordAuthentication no
# 公钥存储文件
AuthorizedKeysFile      .ssh/authorized_keys
```

然后把自己的公钥传到服务器上，使用私钥登录以保证服务器的安全。

**2、域名配置**

注册好域名后，首先给域名添加两条`DNS`解析记录：

![image-20221019004138419](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20221019004138419.png)

如图所示，此处需要替换**记录值**为你的公网`IP`和域名。



注册完成后，申请免费的`ssl`证书，用于后续配置`https`服务或者`tls`证书。如下图所示。

![image-20221019004432831](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20221019004432831.png)

`20`个免费证书绝对够用了。

接着需要做的事情是最耗时的：域名`ICP`备案。不备案的话，是无法访问域名的`80`和`443`端口的。

直接在阿里云里面搜索域名备案，然后按照流程走完备案就行。域名备案中比较麻烦的点：

1. 网站名称不能包含**博客**这两个字，所以需要使用其他名称
2. 记住自己填写的信息，有人会打电话过来审核询问

域名备案大概`1~2`周的时间，通过后会有短信和邮件通知。域名备案完成后，到服务器的安全组把`80`和`443`端口放行。如下图所示：

![image-20221019004949978](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20221019004949978.png)





# 2 hugo使用方法

`hugo`使用非常简单。直接到[官网](https://github.com/gohugoio/hugo/releases)上下载最新版本的`hugo`，建议下载带有`extend`版本的，因为大多数主题都需要扩展版本。

我在`windows`系统上使用`hugo`，所以直接下载`hugo_extended_XXXXX_windows-amd64.zip`，然后解压。

解压后可以把存放`hugo.exe`的文件夹路径加入到系统环境变量，不过我经常使用`powershell`去执行`hugo.exe`，所以我并没有添加。

接下来，执行`hugo.exe new site XXXXXX`， 这里的`XXXXXX`自定义即可，会生成一个目录，里面存放博客的相关文件。

然后`cd XXXXXX`，进入刚刚创建的目录，执行`hugo.exe server`就能在本地起一个`http`服务。访问`http://localhost:1313`就能访问到一个`demo`网站。

如果需要显示草稿，执行`hugo.exe server -D`即可。更多的参数和选项，可以执行`hugo.exe --help`获取。

如果本地查看网站没啥问题了，执行`hugo.exe`，就会在`public`目录下生成相关文件。这个`publibc`就是网站的所有文件。

之后的使用，基本只需要`hugo.exe server -D`和`hugo.exe`两个命令。

# 3 even主题配置

写这篇文章的时候，`even`的作者把之前的很多`pr`都合并了，所以直接拉取代码即可。

## 3.1 配置github小图标

修改`githubForkUrl`为你的`github`地址，配置后的效果如下：

![image-20230113144224324](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230113144224324.png)

可以使用我制作的小图片，点击[这里](https://roderickchan.github.io/img/follow_me_on_github.png)下载，然后放置在`static\img\follow_me_on_github.png`。也可以自己制作图片，图片不要太大，否则容易压盖到其他内容。



## 3.2 配置Back to top按钮

修改`assets\sass\_partial\_back-to-top.scss`文件：

```scss
.back-to-top {
  display: none;
  transition-property: transform;
  transition-timing-function: ease-out;
  transition-duration: 0.3s;
  z-index: 10;
  background-color: $content-blockquote-backgroud;
  position: fixed;
  right: 10px;
  bottom: 10px;
  height: 30px;
  width: 50px;
  text-align: center;
  padding-top: 20px;
  border-radius: 20%;
  overflow: hidden;

  &:hover {
    transform: translateY(-5px); 
  }
  
  .icon-up {
     vertical-align: top;
  }
}

```



效果图如下：

![image-20230113150413459](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230113150413459.png)

## 3.3 配置添加搜索框

来源于[这篇博客](https://sobaigu.com/hugo-set-featuer-search.html)，依葫芦画瓢，自定义一个搜索框即可。

但是我一直没有成功过，后来发现这种代理的博客会直接请求到内部端口上去，目前还不知道咋解决。



## 3.4 配置valine评论系统

我是按照这篇博客进行配置的[Hexo NexT 评论系统 Valine 的使用 - 腾讯云开发者社区-腾讯云 (tencent.com)](https://cloud.tencent.com/developer/article/1965154)，写得非常详细，我就不再复述一遍。



## 3.5 配置访客记录地球仪

[Welcome to RevolverMaps | RevolverMaps - Free 3D Visitor Maps](https://www.revolvermaps.com/)提供了相关的功能，可以在网站首页和每篇博客下面生成一个可拉拽的地球仪，地球仪上记录这访客的国家和地区。因此，你需要去该网站上选一个心仪的地球仪，其会自动生成一段`javascript`代码。

修改`config.toml`文件，添加如下代码：

```toml
[params.revolvermaps]
  enable = true
```

修改`layouts\partials\comments.html`文件，添加代码：

```html
  {{- if .Site.Params.revolvermaps.enable}}
    <script type="text/javascript" src="//rf.revolvermaps.com/0/0/8.js?i=5iujp75b2pp&amp;m=0&amp;c=ff0000&amp;cr1=ffffff&amp;f=arial&amp;l=33" async="async"></script>
  {{- end}}
```

这里显示的是我的配置，你需要把`script`元素的内容替换为你拷贝的代码即可。

效果图如下：

![image-20230113150448435](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230113150448435.png)

# 4 nginx反向代理

使用`nginx`反向代理提供`http(s)`访问服务。

## 4.1 博客文件存放在公网服务器上

目前主流的方法是在写好博客后，执行`hugo`的相关命令，生成`public`目录，然后把整个`public`目录使用`scp`或者`rsync`等工具打包上传到公网服务器上，然后再配置`nginx`反向代理，在配置文件中指定`root`根目录为服务器上的`/xxxx/public`目录。

最开始，我也是这么做的。

假设此时你的域名为`testdomain.com`，那么采用这种方案的配置文件内容为：

```nginx
# /etc/nginx/nginx.conf
user  www-data;
worker_processes auto;
pid /var/run/nginx.pid;
worker_rlimit_nofile 10240;

events {
    use epoll;
    worker_connections 10240;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    charset utf-8;
    autoindex off;
    sendfile on;
    tcp_nopush on;

    types_hash_max_size 2048;
    server_names_hash_max_size 1024;
    server_names_hash_bucket_size 512;
    client_header_buffer_size 16k;
    large_client_header_buffers 4 32k;

    log_format main '[$time_iso8601] $http_x_forwarded_for $remote_addr '
                    '$request_method $scheme://$host$request_uri $status '
                    '$http_user_agent';

    access_log  /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    gzip off;

    server {
        listen 80;
        listen [::]:80;
        server_name testdomain.com www.testdomain.com;
        return 301 https://www.testdomain.com$request_uri; # 重定向到https
    }

    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name testdomain.com www.testdomain.com;
        if ( $host != 'www.testdomain.com' ){
            return 301 https://www.testdomain.com$request_uri;
        }

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
        ssl_session_tickets off;
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:10m;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        ssl_certificate /home/user/blog_server/www.testdomain.com.pem; # 域名的ssl证书文件
        ssl_certificate_key /home/user/blog_server/www.testdomain.com.key; # 域名的ssl证书文件

        location / {
            root /home/user/blog_server/public;
            expires 3d;
            valid_referers none blocked server_names
                *.testdomain.com www.baidu.com www.bing.com duckduckgo.com www.google.com www.sogou.com;
            if ($invalid_referer) {
                return 444;
            }
        }

        location ~* \.(aspx|php)$ {
            access_log off;
            log_not_found off;
            return 444;
        }

        error_page 404 /404.html;
    }
}
```

这份配置文件主要做了两件事情：

- 将`http`重定向到`https`
- 设置静态代理的根目录为`/home/user/blog_server/public`

将上述的文件内容写到`/etc/nginx/nginx.conf`后，启动`nginx`服务，访问`https://testdomain.com`即可访问到你的博客。

但是这种方法有一些显而易见的弊端：

- 需要把博客文件存储在公网服务器上
- `scp/rsync`同步回随着文件的增多而越来越慢
- 如果想给网站提供附件下载功能，对磁盘消耗较大

特别是第三点，由于有时候我会提供题目的附件，当附件积累起来后，阿里云自带的`40G`磁盘根本不够用。所以，我采取的解决方案是将博客文件全部存放到本地，使用`nginx+frp`代理本地的`nginx`服务。将博客文件存放在本地，一来不需要担心磁盘空间不足的问题；二来，博客文件更容易保管和更新；另外，博客的迁移也很方便，只需要修改一下配置文件和配置证书，而不需要重新上传`public`目录。

特别的，当你有多台电脑的时候，使用`syncThings`工具来同步文件，可以做到在多台电脑上同步写博客，写作体验会非常流畅。



## 4.2 博客文件存放在本地

将博客文件存放在本地时的架构图如图所示：

![nignx-frp-pic](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/nignx-frp-pic.png)



箭头与访问请求的方向一致。

从图中可以看出，要想从域名成功的访问到博客文件，需要做的事情有：

- 本地`PC`启动`nginx`服务，设置`root`为`xxxx/public`，监听端口为`9000`
- 使用`frp`进行端口映射，将本地端口`9000`和远程服务器的端口`8000`进行映射
- 远程服务器配置`nginx`，根据域名将请求转发到`127.0.0.1`对应的端口即可

而将本地的其他服务开放出去的步骤也基本是一致的。

根据以上步骤，分别给出对应的操作流程和有关配置文件。

**1. 本地开启nginx服务并设置开启自启动**

由于我使用的是`windows`，所以需要到[这里](http://nginx.org/en/docs/windows.html)下载`windows`版本的`nginx`。

不建议直接双击`nginx.exe`。相关操作命令如下：

```
# 在console中启动nginx
start nginx.exe
# 快速停止服务
nginx.exe -s stop
# 优雅关闭服务
nginx.exe -s quit
# 重启服务
nginx.exe -s reload
```

配置文件在`conf/nginx.conf`，内容如下：

```nginx

#user  nobody;
worker_processes  4;

error_log  logs/error.log;
error_log  logs/error.log  notice;
error_log  logs/error.log  info;

pid        logs/nginx.pid;


events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    gzip  off;

    server {
        # 监听本地的9000端口
        listen       9000;
        server_name  localhost;

        location / {
            # 这里是我的public文件夹的本地目录
            root   D:/XXXXX/testdomain.com/public;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }
}

```

配置好了之后，启动`nginx.exe`，访问`localhost:9000`即可在本地访问博客。

如果要配置`nginx`服务开机自启动，首先需要下载[Releases · winsw/winsw · GitHub](https://github.com/winsw/winsw/releases)，然后将二进制文件复制一份到`nginx`主目录下并重命名为`winsw.exe`，这个目录下面有`nginx.exe`文件和`conf`等子文件夹。接着在当前目录新建一个`nginx.xml`，配置文件如下：

```xml
<service>
    <id>nginx</id>
    <name>nginx_xxxx</name>
    <description>nginx service</description>
    <executable>.\nginx.exe</executable>
    <stopexecutable>.\nginx.exe</stopexecutable>
    <stoparguments>-s stop</stoparguments>
    <onfailure action="restart" delay="60 sec"/>
    <onfailure action="restart" delay="120 sec"/>
    <logmode>append</logmode>
    <logpath>logs</logpath>
</service>
```

然后在`console`里面执行：

```powershell
# 安装服务
./winsw.exe install nginx.xml
# 启动服务
./winsw.exe start nginx.xml
```

执行完成后，浏览器中访问`127.0.0.1:9000`就能看到自己的博客网站。



**2. frp配置**

下载`frp`工具，在本地`PC`上，编写配置文件如下：

```ini
# frpc.ini
[common]
server_addr = 120.xxx.xxx.xxx
server_port = xxxxx
token = xxxxx
tls_enable = true

[plugin_static_file]
type = tcp
remote_port = 8001
plugin = static_file
plugin_local_path = D:/xxxxx/blog_download_files
plugin_http_user = admin
plugin_http_passwd = admin123

# blog https
[blog_https]
type = tcp
use_compression = true
use_encryption = true
remote_port = 8000
local_ip = localhost
local_port = 9000
```

在远程的`8001`有一个下载服务，远程的`8000`可以访问本地的博客。

同样的，给出`winsw`使用的配置文件，使得`frpc`服务可以开机自启动：

```xml
<service>
    <id>frpc</id>
    <name>frp_windows_amd64</name>
    <description>frpc client</description>
    <executable>E:\frp_windows_amd64\frpc.exe</executable>
    <arguments>-c E:\frp_windows_amd64\frpc.ini</arguments>
    <onfailure action="restart" delay="60 sec"/>
    <onfailure action="restart" delay="120 sec"/>
    <logmode>append</logmode>
    <logpath>logs</logpath>
</service>
```



**3. 公网服务器nginx配置**

在公网服务器上，根据不同的域名配置转发规则，配置文件如下

```nginx
# /etc/nginx/nginx.conf

user  www-data;
worker_processes auto;
pid /var/run/nginx.pid;
worker_rlimit_nofile 10240;

events {
    use epoll;
    worker_connections 10240;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    charset utf-8;
    autoindex off;
    sendfile on;
    tcp_nopush on;

    types_hash_max_size 2048;
    server_names_hash_max_size 1024;
    server_names_hash_bucket_size 512;
    client_header_buffer_size 16k;
    large_client_header_buffers 4 32k;

    log_format main '[$time_iso8601] $http_x_forwarded_for $remote_addr '
                    '$request_method $scheme://$host$request_uri $status '
                    '$http_user_agent';

    access_log  /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    gzip off;

    server {
        listen 80;
        listen [::]:80;
        server_name testdomain.com www.testdomain.com;
        return 301 https://www.testdomain.com$request_uri;
    }
    server {
        listen 80;
        listen [::]:80;
        server_name download.testdomain.com;
        return 301 https://download.testdomain.com$request_uri;
    }

    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name download.testdomain.com;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
        ssl_session_tickets off;
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:10m;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        ssl_certificate /home/user/blog_server/download.testdomain.com.pem;
        ssl_certificate_key /home/user/blog_server/download.testdomain.com.key;

        location / {
                proxy_pass http://127.0.0.1:8001;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto https;

                }
        }


    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name testdomain.com www.testdomain.com;
        if ( $host != 'www.testdomain.com' ){
            return 301 https://www.testdomain.com$request_uri;
        }

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
        ssl_session_tickets off;
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:10m;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        ssl_certificate /home/user/blog_server/www.testdomain.com.pem;
        ssl_certificate_key /home/user/blog_server/www.testdomain.com.key;

        location / {
                proxy_pass http://127.0.0.1:8000;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto https;
        }

        location ~* \.(aspx|php)$ {
            access_log off;
            log_not_found off;
            return 444;
        }

        error_page 404 /404.html;
    }
}
```

这里我配置了`testdomain.com`提供博客访问，`download.testdomain.com`提供文件下载。

并且，`8000/8001`端口可以设置防火墙规则，禁止外部访问。



**4. nginx负载均衡配置**

如果把博客文件放在本地，只使用一个电脑可能不够保险，会面临着断网的风险。比如，我是用以前的旧的笔记本作为服务器放置在学校实验室的机房，运行了好几个月没啥问题，结果寒假期间莫名其妙校园网断掉了，返校后才发现校园网的无感认证好像并没有生效:joy:

为了保险起见，我在实验室的台式机和自己的电脑上使用的相同的配置去配置`nginx`和`frpc`，用`syncThing`去同步文件(现在硬盘不值钱，随便同步)，然后到公网服务器上配置了负载均衡。

参考[Full Example Configuration | NGINX](https://www.nginx.com/resources/wiki/start/topics/examples/full/)，配置一下负载均衡策略即可，我是用是默认的~~毕竟个人网站，不需要什么花里花哨的策略~~。

```nginx
upstream big_server_com {
    server 127.0.0.3:8000 weight=5;
    server 127.0.0.3:8001 weight=5;
    server 192.168.0.1:8000;
    server 192.168.0.1:8001;
  }

  server { # simple load balancing
    listen          80;
    server_name     big.server.com;
    access_log      logs/big.server.access.log main;

    location / {
      proxy_pass      http://big_server_com;
    }
  }
```



# 5 教程总结

总结了使用`hugo + enev + aliyun`配置博客的过程。


纸上得来终觉浅，绝知此事要躬行。

任何教程，不如实际操作一遍。



# 6 引用与参考

编写本文时参考了以下博客：

- https://edward852.github.io/post/%E8%BF%81%E7%A7%BB%E5%8D%9A%E5%AE%A2%E5%88%B0hugo/
- https://lucumt.info/post/hugo/share-experience-for-using-hugo-even-theme/


---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2022-10-11-%E4%BD%BF%E7%94%A8aliyun-hugo%E6%90%AD%E5%BB%BA%E4%B8%AA%E4%BA%BA%E5%8D%9A%E5%AE%A2/  

