YaH3C
=====

YaH3C 最初由 [humiaozuzu](https://github.com/humiaozuzu/) 开发，支持中山大学东校区的校园网认证。

如果你觉得获益良多，可以考虑点击[原项目主页](https://github.com/humiaozuzu/YaH3C/)上的链接进行捐款。

经过修改，该版本 YaH3C 通过模仿华工北校区翼起来客户端（俗称蝴蝶客户端）的 EAPOL 行为进行认证。需要注意的是：

+ 精力有限，该客户端仅仅在北校区北十二宿舍楼测试过，如果在其它宿舍使用出问题，欢迎提交 issues
+ 不提供不断网，欠费上网的功能

开发原因
---------------

+ 翼起来客户端不支持 Linux
+ 不想额外购置可以使用 Scutclient 的路由器
+ Scutclient 在 PC 上编译好后认证失败， 并且其使用 C++ 编写，不想看..

依赖
------------
 
* 主流Linux发行版，包括OpenWrt/DD-WRT
* Python2
* python-netifaces

安装
------------

首先，从github上下载，可以直接利用`git clone`，也可以下载压缩包自己解压然后安装。下面以git为例，如果没有则需要先安装：

```bash
# Ubuntu/Debian
sudo apt-get install git

# ArchLinux
sudo pacman -S git
```

然后，请配置好静态 IP 配置以及安装 python-netifaces：

``bash
# Ubuntu/Debian
sudo apt-get install python-netifaces

#Archlinux
sudo pacman -S python2-netifaces

```

最后，从项目中clone下来并安装

```bash
git clone https://github.com/tatsuteng/YaH3C.git
cd YaH3C
sudo python setup.py install
```

**ArchLinux**默认安装的python是python3，你需要手动安装python2。

使用
----

### 认证

程序运行时必须要有root权限：

```bash
sudo yah3c
```

根据程序的提示输入账号密码就可以开始认证了，有些选项如果看不懂请直接按`Enter`。

### 关于 dhcp_command

dhcp_command 用于认证后获取 IP 地址，但是由于华工北校区在静态 IP 基础上进行认证，

所以不需要额外的命令获取 IP 地址，在建立帐号时遇到该提示直接按`Enter`即可。

``` bash
$ yah3c -h       
usage: yah3c [-h] [-u USERNAME] [-debug]

Yet Another H3C Authentication Client

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Login in with this username
  -debug                Enable debugging mode
```

如执行`sudo yah3c -u Maple`可以自动认证`Maple`这个帐号

配置文件格式
---------
用户的登陆信息按照如下的格式保存在文件`/etc/yah3c.conf`中：

``` ini
[account]                  # 你的帐户 
password = 123456          # 密码
ethernet_interface = eth0  # 使用的网卡，默认为eth0
dhcp_command = dhcpcd      # 验证成功后使用的dhcp命令(dhcpcd/dhclient)，默认为空
daemon = True              # 验证成功后是否变成daemon进程，默认为是
```

ScreenShots
-----------

认证成功:

![success](https://raw.github.com/tatsuteng/YaH3C/master/screenshots/success.png)

认证失败:

![failure](https://raw.github.com/tatusteng/YaH3C/master/screenshots/failure.png)

License
-------
YaH3c的代码使用MIT License发布，此外，禁止使用YaH3C以及YaH3C的修改程序用于商业目的（比如交叉编译到路由进行销售等行为）
