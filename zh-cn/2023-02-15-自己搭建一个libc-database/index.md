# 自己搭建一个libc database


> 为什么要自己搭建一个 `libc database` 呢，~~因为官方的<https://libc.rip/api/>查询接口挂了~~官方的查询接口时好时坏，现在又可以用了。

<!--more-->
{{< admonition >}}
如果官方的接口可用，我就会暂时下线自己部署的接口 <https://libc.roderickchan.cn>。

如果你发现官方的接口用不了了，请及时联系(`email`)我，我会重启服务。
{{< /admonition >}}


为什么要自己搭建一个`libc database`呢，因为~~写文章的时候~~官方的<https://libc.rip/api/>查询接口挂了。而我写的`pwncli`中的`LibcBox`依赖这个接口，挂了之后直接影响了`LibcBox`的使用。既然不能白嫖了，那不如自己动手搭建一个。自己动手，丰衣足食。

# 下载项目

从[niklasb/libc-database: Build a database of libc offsets to simplify exploitation (github.com)](https://github.com/niklasb/libc-database)下载源码，下载后，先安装一下必备的软件包：

```bash
sudo apt-get update && \
sudo apt-get install -y \
  binutils file \
  wget \
  rpm2cpio cpio \
  zstd jq nodejs npm
  
pip3 install elasticsearch==7.0.0 # 最好装这个版本的，否则会遇到很多奇怪的问题
```



安装结束后，先执行`./get all`然后等待一两分钟后直接<kbd>Ctrl</kbd>+<kbd>C</kbd>。不要等待这个操作执行完，该命令非常耗时，执行完大概要等一个小时左右。因此，可以先下载一部分用于测试。



# 文件修改

## 域名

直接使用`vscode`的全局替换，把所有的`https://libc.rip`替换为`https://yourdomain.com`。

## index

然后对`index.py`修改如下：

```diff
- es = Elasticsearch()
+ es = Elasticsearch(config.ES_HOST)
```

## nginx.conf

由于我本身就使用了`nginx`服务器，所以我把配置添加到`/etc/nginx/nginx.conf`。

记得申请证书并把证书放置在服务器上。



除此之外，可以修改`docker-compose.yaml`中的端口映射，避免端口冲突。



# 前端生成

在`libc-database/searchengine/frontend`中执行：

```bash
npm install
npm run build
```



# 构建镜像

使用在`libc-database/searchengine`，使用`docker compose up -d`构建镜像。

可以使用阿里云的镜像，替换`/etc/sources.list`和`/etc/pip.conf`。

# 生成索引

在`libc-database/searchengine`执行`python3 -m index ../db`



# 接口测试

测试查询接口：

```bash
curl -X POST -H 'Content-Type: application/json' --data \
     '{"symbols": {"strncpy": "db0", "strcat": "0x000000000d800"}}' \
     'https://yourdoamin.com/api/find'
```

无异常说明部署成功了。



访问`https://yourdoamin.com`访问前端页面。

# 全部更新

测试接口没问题之后，在`libc-database/searchengine`，执行`./update.sh`。建议把`update.sh`修改为：

```bash
#!/bin/bash
cd "$(dirname "$0")"
cd ..
./get all
cd searchengine
python3 -m index ../db
```

等待`update.sh`执行完成，就完事儿了。



# 访问我的

点击：<https://libc.roderickchan.cn>可以在线查询

![image-20230215163236241](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230215163236241.png)

还可以使用下面的命令查询。

```bash
curl -X POST -H 'Content-Type: application/json' --data \
     '{"symbols": {"system": "290", "puts": "0x000420"}}' \
     'https://libc.roderickchan.cn/api/find'
```

![image-20230215163211200](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230215163211200.png)

接口已同步更新到`pwncli`中，`pwncli`的使用方式为：

```python
from pwncli import *

lb = LibcBox()
lb.add_symbol('system', 0x290)
lb.search()
```



---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2023-02-15-%E8%87%AA%E5%B7%B1%E6%90%AD%E5%BB%BA%E4%B8%80%E4%B8%AAlibc-database/  

