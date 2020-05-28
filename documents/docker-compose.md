1. 什么是Docker-Compose

Compose项目来源于之前的fig项目，使用python语言编写,与docker/swarm配合度很高。

Compose 是 Docker 容器进行编排的工具，定义和运行多容器的应用，可以一条命令启动多个容器，使用Docker Compose不再需要使用shell脚本来启动容器。 

Compose 通过一个配置文件来管理多个Docker容器，在配置文件中，所有的容器通过services来定义，然后使用docker-compose脚本来启动，停止和重启应用，和应用中的服务以及所有依赖服务的容器，非常适合组合使用多个容器进行开发的场景。

docker-compose默认的模板文件是 docker-compose.yml，其中定义的每个服务都必须通过 image 指令指定镜像或 build 指令（需要 Dockerfile）来自动构建。

其它大部分指令都跟 docker run 中的类似。

如果使用 build 指令，在 Dockerfile 中设置的选项(例如：CMD, EXPOSE, VOLUME, ENV 等) 将会自动被获取，无需在 docker-compose.yml 中再次设置。
使用Compose 基本上分为三步：

1.Dockerfile 定义应用的运行环境
2.docker-compose.yml 定义组成应用的各服务
3.docker-compose up 启动整个应用


2.安装Compose

两种docker-compose安装方式

1.从github上下载docker-compose二进制文件安装

下载最新版的docker-compose文件 

$ sudo curl -L https://github.com/docker/compose/releases/download/1.16.1/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
添加可执行权限 
$ sudo chmod +x /usr/local/bin/docker-compose
测试安装结果 

$ docker-compose --version 
docker-compose version 1.16.1, build 1719ceb
2.pip安装

2.1、安装python-pip

yum -y install epel-release
yum -y install python-pip
2.2、安装docker-compose
pip install docker-compose
待安装完成后，执行查询版本的命令，即可安装docker-compose

[root@swarm01 fendo]# docker-compose version
docker-compose version 1.21.2, build a133471
docker-py version: 3.3.0
CPython version: 2.7.5
OpenSSL version: OpenSSL 1.0.2k-fips  26 Jan 2017
3.docker-compose.yml 配置文件详解

docker-compose文件结构,官方提供了一个 yaml Docker Compose 配置文件的标准例子

version: "3"
services:

  redis:
    image: redis:alpine
    ports:
      - "6379"
    networks:
      - frontend
    deploy:
      replicas: 2
      update_config:
        parallelism: 2
        delay: 10s
      restart_policy:
        condition: on-failure

  db:
    image: postgres:9.4
    volumes:
      - db-data:/var/lib/postgresql/data
    networks:
      - backend
    deploy:
      placement:
        constraints: [node.role == manager]

  vote:
    image: dockersamples/examplevotingapp_vote:before
    ports:
      - 5000:80
    networks:
      - frontend
    depends_on:
      - redis
    deploy:
      replicas: 2
      update_config:
        parallelism: 2
      restart_policy:
        condition: on-failure

  result:
    image: dockersamples/examplevotingapp_result:before
    ports:
      - 5001:80
    networks:
      - backend
    depends_on:
      - db
    deploy:
      replicas: 1
      update_config:
        parallelism: 2
        delay: 10s
      restart_policy:
        condition: on-failure

  worker:
    image: dockersamples/examplevotingapp_worker
    networks:
      - frontend
      - backend
    deploy:
      mode: replicated
      replicas: 1
      labels: [APP=VOTING]
      restart_policy:
        condition: on-failure
        delay: 10s
        max_attempts: 3
        window: 120s
      placement:
        constraints: [node.role == manager]

  visualizer:
    image: dockersamples/visualizer:stable
    ports:
      - "8080:8080"
    stop_grace_period: 1m30s
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock"
    deploy:
      placement:
        constraints: [node.role == manager]

networks:
  frontend:
  backend:

volumes:
  db-data:
一份标准配置文件应该包含 version、services、networks 三大部分，其中最关键的就是 services 和 networks 两个部分

3.1、文件配置

compose 文件是一个定义服务、 网络和卷的 YAML 文件 。Compose 文件的默认路径是 ./docker-compose.yml

服务定义包含应用于为该服务启动的每个容器的配置，就像传递命令行参数一样 docker container create。同样，网络和卷的定义类似于 docker network create 和 docker volume create。

正如 docker container create 在 Dockerfile 指定选项，如 CMD、 EXPOSE、VOLUME、ENV，在默认情况下，你不需要再次指定它们docker-compose.yml。

可以使用 Bash 类 ${VARIABLE} 语法在配置值中使用环境变量。

提示: 可以是用 .yml 或 .yaml 作为文件扩展名

3.2、版本

Compose目前为止有三个版本分别为Version 1,Version 2,Version 3,Compose区分Version 1和Version 2（Compose 1.6.0+，Docker Engine 1.10.0+）。Version 2支持更多的指令。Version 1没有声明版本默认是"version 1"。Version 1将来会被弃用。

3.3、配置选项

１.bulid

服务除了可以基于指定的镜像，还可以基于一份 Dockerfile，在使用 up 启动之时执行构建任务，这个构建标签就是 build，它可以指定 Dockerfile 所在文件夹的路径。Compose 将会利用它自动构建这个镜像，然后使用这个镜像启动服务容器
build: /path/to/build/dir
也可以是相对路径

build: ./dir
设定上下文根目录，然后以该目录为准指定 Dockerfile

build:
  context: ../
  dockerfile: path/of/Dockerfile

2. context

context 选项可以是 Dockerfile 的文件路径，也可以是到链接到 git 仓库的url，当提供的值是相对路径时，它被解析为相对于撰写文件的路径，此目录也是发送到 Docker 守护进程的 context

build:
  context: ./dir
３. dockerfile

使用此 dockerfile 文件来构建，必须指定构建路径
build:
  context: .
  dockerfile: Dockerfile-alternate
4.image

services:
  web:
    image: nginx
在 services 标签下的第二级标签是 web，这个名字是用户自己自定义，它就是服务名称。
image 则是指定服务的镜像名称或镜像 ID。如果镜像在本地不存在，Compose 将会尝试拉取这个镜像。
例如下面这些格式都是可以的：
image: redis
image: ubuntu:14.04
image: tutum/influxdb
image: a4bc65fd

5. args

添加构建参数，这些参数是仅在构建过程中可访问的环境变量
首先， 在Dockerfile中指定参数：
ARG fendo
ARG password

RUN echo "Build number: $fendo"
RUN script-requiring-password.sh "$password"
然后指定 build 下的参数,可以传递映射或列表

build:
  context: .
  args:
    fendo: 1
    password: fendo
或

build:
  context: .
  args:
    - fendo=1
    - password=fendo
指定构建参数时可以省略该值，在这种情况下，构建时的值默认构成运行环境中的值

args:

  - fendo
  - password
    6.command

使用 command 可以覆盖容器启动后默认执行的命令。

command: bundle exec thin -p 3000
该命令也可以是一个列表，方法类似于 dockerfile:

command: ["bundle", "exec", "thin", "-p", "3000"]
7.container_name

Compose 的容器名称格式是：<项目名称><服务名称><序号>

虽然可以自定义项目名称、服务名称，但是如果你想完全控制容器的命名，可以使用这个标签指定：

container_name: app
这样容器的名字就指定为 app 了。

8.depends_on

在使用 Compose 时，最大的好处就是少打启动命令，但是一般项目容器启动的顺序是有要求的，如果直接从上到下启动容器，必然会因为容器依赖问题而启动失败。

例如在没启动数据库容器的时候启动了应用容器，这时候应用容器会因为找不到数据库而退出，为了避免这种情况我们需要加入一个标签，就是 depends_on，这个标签解决了容器的依赖、启动先后的问题。

例如下面容器会先启动 redis 和 db 两个服务，最后才启动 web 服务：

version: '3'
services:
  web:
    build: .
    depends_on:
      - db
      - redis
  redis:
    image: redis
  db:
    image: postgres
注意的是，默认情况下使用 docker-compose up web 这样的方式启动 web 服务时，也会启动 redis 和 db 两个服务，因为在配置文件中定义了依赖关系。

9.pid

pid: "host"
将PID模式设置为主机PID模式，跟主机系统共享进程命名空间。容器使用这个标签将能够访问和操纵其他容器和宿主机的名称空间。

10.ports

映射端口的标签。

使用HOST:CONTAINER格式或者只是指定容器的端口，宿主机会随机映射端口。

ports:

 - "3000"
 - "8000:8000"
 - "49100:22"
 - "127.0.0.1:8001:8001"
   注意：当使用HOST:CONTAINER格式来映射端口时，如果你使用的容器端口小于60你可能会得到错误得结果，因为YAML将会解析xx:yy这种数字格式为60进制。所以建议采用字符串格式。
   11.extra_hosts

添加主机名的标签，就是往/etc/hosts文件中添加一些记录，与Docker client的--add-host类似：

extra_hosts:

 - "somehost:162.242.195.82"
 - "otherhost:50.31.209.229"
   启动之后查看容器内部hosts：

162.242.195.82  somehost
50.31.209.229   otherhost

12.volumes

挂载一个目录或者一个已存在的数据卷容器，可以直接使用 [HOST:CONTAINER] 这样的格式，或者使用 [HOST:CONTAINER:ro] 这样的格式，后者对于容器来说，数据卷是只读的，这样可以有效保护宿主机的文件系统。
Compose的数据卷指定路径可以是相对路径，使用 . 或者 .. 来指定相对目录。

数据卷的格式可以是下面多种形式：

volumes:
  // 只是指定一个路径，Docker 会自动在创建一个数据卷（这个路径是容器内部的）。

  - /var/lib/mysql

  // 使用绝对路径挂载数据卷

  - /opt/data:/var/lib/mysql

  // 以 Compose 配置文件为中心的相对路径作为数据卷挂载到容器。

  - ./cache:/tmp/cache

  // 使用用户的相对路径（~/ 表示的目录是 /home/<用户目录>/ 或者 /root/）。

  - ~/configs:/etc/configs/:ro

  // 已经存在的命名的数据卷。

  - datavolume:/var/lib/mysql
    如果你不使用宿主机的路径，你可以指定一个volume_driver。

volume_driver: mydriver
原文：https://blog.csdn.net/u011781521/article/details/80464826 
