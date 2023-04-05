# nginx配置的问题记录


> 当域名没有规则匹配的时候，`nginx`的处理过程让我迷惑。

<!--more-->

`rt`，当域名没有规则匹配的时候，`nginx`的处理过程让我感到迷惑。

# 问题复现

## 问题描述

事情是这样的。

好些天前，为了在公网服务器上搭建一个`chatgpt`的`web`版本服务，我申请了子域名`chatgpt.roderickchan.cn`，配置好了`DNS`解析规则并申请了对应的`ssl`证书。

我之前的`nginx`配置是这样的：`/etc/nginx/nginx.conf`为主要的配置文件，设置一些公共的参数、规则等，`/etc/nginx/conf.d/*.conf*`会存放不同的域名的规则。
我的`/etc/nginx/nginx.conf`内容如下：
```nginx
user www-data;
worker_processes auto;
pid /var/run/nginx.pid;
worker_rlimit_nofile 1024;

events {
    use epoll;
    worker_connections 1024;
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
    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }
    log_format main
        '[$time_iso8601] $http_x_forwarded_for $remote_addr '
        '$request_method $scheme://$host$request_uri $status '
        '$http_user_agent';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    gzip off;
    include /etc/nginx/conf.d/*.conf;

}
```
再正常不过的配置。

每当我申请了`xxx.roderickchan.cn`域名的时候，就会在`/etc/nginx/conf.d`目录下新增`xxx.roderickchan.cn.conf`文件，文件填入的内容如下：
```nginx
upstream xxxxx {
	ip_hash;
    server 127.0.0.1:12345;
    server 127.0.0.1:12346;
    server 127.0.0.1:12347;
}

server {
    listen 80;
    listen [::]:80;
    server_name xxxxx.roderickchan.cn;
    return 301 https://xxxxx.roderickchan.cn$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name xxxxx.roderickchan.cn;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    ssl_session_tickets off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    add_header Strict-Transport-Security
        "max-age=31536000; includeSubDomains"
        always;
    ssl_certificate /home/xxxx.pem;
    ssl_certificate_key /home/xxxxx.key;

    location / {
        proxy_pass http://xxxxx;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

    }
}
```
该配置文件主要干了以下几件事：
- 配置了负载均衡策略
- 设置了`http`强制跳转`https`
- 设置了`https`的相关参数

服务搭建好后，使用了一段时间没啥问题。直到今天，我临时把服务取消了，并把文件`xxx.roderickchan.cn.conf`修改为了`xxx.roderickchan.cn.conf.notuse`，以为这样就访问不到子域名，也访问不到服务了。

然后，当我用浏览器访问`http://xxx.roderickchan.cn`的时候，发现被跳转到了`https://yyy.roderickchan.cn`（我的另一个子域名），并且提示了证书不匹配的错误。证书不匹配很好理解，因为`https://yyy.roderickchan.cn`提供的证书是为`yyy.roderickchan.cn`签发的，而我访问的是`xxx.roderickchan.cn`。

发现问题后，我一拍脑袋，直接让所有域名的`http`都跳转到`https`不就行了，这样访问`https`肯定会失败。

## 尝试解决
于是，我立马对`/etc/nginx/nginx.conf`进行了修改，修改后的`conf`文件为：
```nginx
# ......
http {
    # ....
	server {
	    listen 80;
	    listen [::]:80;
	    server_name _;
	    return 301 https://$host/$request_uri;
    }
    include /etc/nginx/conf.d/*.conf;
}
```

在`80`端口上，为所有没有匹配到的域名设置了强制跳转`https`。

我以为接下来访问`http://xxx.roderickchan.cn`的流程会像这样：
1. 访问`http://xxx.roderickchan.cn`
2. 重定向到`https://xxx.roderickchan.cn`
3. 找不到`http://xxx.roderickchan.cn`的`ssl`证书
4. 访问失败

用`curl`测试了一下，发现真的会失败：
```shell
$ curl -L -v -i http://chatgpt.roderickchan.cn
*   Trying 120.25.122.195:80...
* TCP_NODELAY set
* Connected to chatgpt.roderickchan.cn (120.25.122.195) port 80 (#0)
> GET / HTTP/1.1
> Host: chatgpt.roderickchan.cn
> User-Agent: curl/7.68.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 301 Moved Permanently
HTTP/1.1 301 Moved Permanently
< Server: nginx/1.18.0 (Ubuntu)
Server: nginx/1.18.0 (Ubuntu)
< Date: Sat, 01 Apr 2023 09:12:30 GMT
Date: Sat, 01 Apr 2023 09:12:30 GMT
< Content-Type: text/html
Content-Type: text/html
< Content-Length: 178
Content-Length: 178
< Connection: keep-alive
Connection: keep-alive
< Location: https://chatgpt.roderickchan.cn/
Location: https://chatgpt.roderickchan.cn/

<
* Ignoring the response-body
* Connection #0 to host chatgpt.roderickchan.cn left intact
* Clear auth, redirects to port from 80 to 443Issue another request to this URL: 'https://chatgpt.roderickchan.cn/'
*   Trying 120.25.122.195:443...
* TCP_NODELAY set
* Connected to chatgpt.roderickchan.cn (120.25.122.195) port 443 (#1)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN, server accepted to use h2
* Server certificate:
*  subject: CN=download.roderickchan.cn
*  start date: Nov 12 00:00:00 2022 GMT
*  expire date: Nov 12 23:59:59 2023 GMT
*  subjectAltName does not match chatgpt.roderickchan.cn
* SSL: no alternative certificate subject name matches target host name 'chatgpt.roderickchan.cn'
* Closing connection 1
* TLSv1.3 (OUT), TLS alert, close notify (256):
curl: (60) SSL: no alternative certificate subject name matches target host name 'chatgpt.roderickchan.cn'
More details here: https://curl.haxx.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

`But`，失败的错误是`no alternative certificate subject name matches target host name `，服务器给我的证书的域名仍然是`download.roderickchan.cn`，这就离离原上谱了。

## 问题定位

那么问题来了，我都没有为`nginx`配置`xxx.roderickchan.cn`这个子域名的处理规则，为啥浏览器访问会跳转到`https://yyy.roderickchan.cn`。
怀着这样的疑惑，我在互联网上搜索了好一阵。直到在`stackoverflow`上找到这么一个问题：[Why is nginx responding to any domain name? - Stack Overflow](https://stackoverflow.com/questions/9824328/why-is-nginx-responding-to-any-domain-name)

这个问题，不正是我的问题么！

根据这个问题下面的回答，我找到了官方文档：[How nginx processes a request](http://nginx.org/en/docs/http/request_processing.html)。看到了这一段：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/2023-04-01_182248.png)


到这里，我~~终于~~暂时破案了。

由于我没有指定`default_server`，那么我的`yyy.roderickchan.cn.conf`（按字母排序是第一个）中的第一个`server`会被当做为`default_server`，所以我的请求链是这样的：
`http://xxx.roderickchan.cn` ---> `nginx`没有找到`xxx.roderickchan.cn`处理规则，寻找`default_server` ---> `nginx`没有找到显式定义的`default_server` ---> `nginx`根据加载的`server`顺序跳转到`http://yyy.roderickchan.cn` ---> 被重定向到`https://yyy.roderickchan.cn`。

至此，我终于搞明白了为啥访问`http://xxx.roderickchan.cn`会被重定向到`https://yyy.roderickchan.cn`。

只需要定义好`default_server`就能把所有的没有匹配到的域名给处理了。

说干就干~

# 解决方案

## 解决方案1
很快啊，我就写好了匹配规则，修改后的配置文件为：
```nginx
# ......
http {
    # ....
	server {
	    listen 80 default_server;
	    listen [::]:80 default_server;
	    listen 443 ssl default_server;
	    listen [::]:443 ssl default_server;
	    server_name _;
	    ssl_certificate /home/xxx/www.roderickchan.cn.pem;
	    ssl_certificate_key /home/xxx/www.roderickchan.cn.key;
	    return 403;
    }
    include /etc/nginx/conf.d/*.conf;
}
```

设置了`default_server`，直接用了`www.roderickchan.cn`的证书。心想这次没问题，用`curl`测试一下，没想到又一次离谱了起来。
测试访问`http://chatgpt.roderickchan.cn`
```shell
$ curl -L -v -i http://chatgpt.roderickchan.cn
*   Trying 120.25.122.195:80...
* TCP_NODELAY set
* Connected to chatgpt.roderickchan.cn (120.25.122.195) port 80 (#0)
> GET / HTTP/1.1
> Host: chatgpt.roderickchan.cn
> User-Agent: curl/7.68.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 Forbidden
HTTP/1.1 403 Forbidden
< Server: nginx/1.18.0 (Ubuntu)
Server: nginx/1.18.0 (Ubuntu)
< Date: Sat, 01 Apr 2023 10:53:19 GMT
Date: Sat, 01 Apr 2023 10:53:19 GMT
< Content-Type: text/html; charset=utf-8
Content-Type: text/html; charset=utf-8
< Content-Length: 162
Content-Length: 162
< Connection: keep-alive
Connection: keep-alive

<
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
* Connection #0 to host chatgpt.roderickchan.cn left intact
```

确实给出了`403`的错误，没有问题。继续测试`https`访问：
```shell
$ curl -L -v -i https://chatgpt.roderickchan.cn
*   Trying 120.25.122.195:443...
* TCP_NODELAY set
* Connected to chatgpt.roderickchan.cn (120.25.122.195) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
* ALPN, server accepted to use h2
* Server certificate:
*  subject: CN=www.roderickchan.cn
*  start date: Sep 27 00:00:00 2022 GMT
*  expire date: Sep 27 23:59:59 2023 GMT
*  subjectAltName does not match chatgpt.roderickchan.cn
* SSL: no alternative certificate subject name matches target host name 'chatgpt.roderickchan.cn'
* Closing connection 0
* TLSv1.2 (OUT), TLS alert, close notify (256):
curl: (60) SSL: no alternative certificate subject name matches target host name 'chatgpt.roderickchan.cn'
More details here: https://curl.haxx.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```
又找到`subject: CN=www.roderickchan.cn`去了·····

所以，`nginx`根据证书，又给重定向到了`www.roderickchan.cn`，然后，检测到证书与匹配，报错。

那么，给一个非法的域名的签名证书是不是就可以解决了。

## 解决方案2

采用一个自签名的证书，替换到合法的域名的证书即可。

使用`openssl`生成自签名证书：
```bash
openssl genrsa -out server.key 4096
openssl req -new -x509 -days 3650 -key server.key -out server.crt -subj "/C=CN/ST=mykey/L=mykey/O=mykey/OU=mykey/CN=domain1/CN=domain2/CN=domain3"
```

最后会生成`server.crt`和`server.key`两个文件，替换掉就好了。

最最最终的配置文件为：
```nginx
# ......
http {
    # ....
	server {
	    listen 80 default_server;
	    listen [::]:80 default_server;
	    listen 443 ssl default_server;
	    listen [::]:443 ssl default_server;
	    server_name _;
	    ssl_certificate /home/xxx/server.crt;
	    ssl_certificate_key /home/xxx/server.key;
	    return 403;
    }
    include /etc/nginx/conf.d/*.conf;
}
```

最后用`curl`测试一下：
```shell
$ curl -L -v -i https://chatgpt.roderickchan.cn
*   Trying 120.25.122.195:443...
* TCP_NODELAY set
* Connected to chatgpt.roderickchan.cn (120.25.122.195) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (OUT), TLS alert, unknown CA (560):
* SSL certificate problem: self signed certificate
* Closing connection 0
curl: (60) SSL certificate problem: self signed certificate
More details here: https://curl.haxx.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

`SSL certificate problem: self signed certificate`，浏览器上访问也会得到`403`了。

至此，终于解决了这个问题。

# 总结

- `nginx`处理没有匹配到的域名的时候，会走`default_server`
- 如果没有显式指定`default_server`，会把加载的第一个`server`当成`default_server`
- `nginx`的加载顺序，根据`nginx.conf`的规则顺序，然后根据配置文件的`ascii`排序进行加载

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2023-04-01-nginx-config-problem/  

