
# LazyCrasher

## 简介

一个自动检测 AFL crashes 输出的脚本，可以添加定时任务执行，自动检测 crashes 文件夹中是否有新的崩溃产生并发送通知。如果已经安装 afl-utils，可自动调用 afl-collect 以进一步处理crashes。


## 使用说明

```shell
✗ python3 listen.py --help           
usage: listen.py [-h] [-d DATA_PATH] [-t TIME] [-s SOFTWARE] [-l LOG_LEVEL] [-v]

Lazycrasher opts

options:
  -h, --help            show this help message and exit
  -d DATA_PATH, --data-path DATA_PATH
                        Path to save fuzz projects' input & output data [Default: ./AFL_Fuzz_Datas]
  -t TIME, --time TIME  Set the time from the current time when the search crash occurs
  -s SOFTWARE, --software SOFTWARE
                        Software to search for fuzz projects, Default: None (Search All fuzz projects)
  -l LOG_LEVEL, --log-level LOG_LEVEL
                        Level of Sending message: [0] Send message when find new crashes(not collect) [Default] | [1] Send message when find useful crashes (after collect)
  -v, --verbose         Show all debug messages
```


## 运行

手动执行：

```
$ python3 listen.py -d Datas -l 1 -t 20 -v 
```

定时运行：添加到 crontab

```
start.sh 参数1 (参数1为给listen.py的 --time 参数)
# 7-22点之间每隔两个小时执行一次脚本
0 7-22/2 * * * <path>/start.sh 120
```

## 流程

### Step 1: 手动启动 AFL fuzzer

```shell
$ afl-fuzz -M fuzzer01 -i <AFL_Fuzz_Datas_Path>/<Project_name>/input -o <AFL_Fuzz_Datas>/<Project_name>/output -- <target> --target-opts
$ afl-fuzz -S fuzzer02 -i <AFL_Fuzz_Datas_Path>/<Project_name>/input -o <AFL_Fuzz_Datas>/<Project_name>/output -- <target> --target-opts
```

注意:

- 运行 `afl-fuzz` 时尽量使用绝对路径指定目录和可执行程序


AFL input & output 文件夹结构:

```shell
AFL_Fuzz_Datas
├── vim
│   ├── input
│   ├── output
│       ├── fuzzer01
│           ├── crashes
│       ├── fuzzer02
│   ├── collections
│       ├── README.txt (copy from fuzzer*/crashes/README.txt)
├── gpac
│   ├── input
│   ├── output
```

### Step 2: 运行该脚本用于监听crashes文件夹

crashes 路径: `<AFL_Fuzz_Datas>/<Project_name>/output/<fuzzer01>/crashes/`

脚本执行后，它将会扫描 crashes 目录，当检测到有新的 crash 产生时进行下一步操作

### Step 3: 调用 afl-collect (如果可用)

如果 `afl-collect` 可用 (已安装 [afl-utils](https://gitlab.com/rc0r/afl-utils) ), 那么执行 `afl-collect` 用于收集和处理crashes

将会执行以下命令:

```shell
$ afl-collect -j 8 -e gdb_script -r -rr <AFL_Fuzz_Datas>/<Project_name>/output <AFL_Fuzz_Datas>/<Project_name>/collections -- <target> --target-opts
```

#### Step 3-1: crashe去重 

使用 collect 后的 crashes 运行程序，获取 ASAN 的 SUMMARY 输出信息，根据行号信息剔除重复项(保留无法获取 ASAN Summary的crashes), 并进行重命名便于人工进行下一步分析 (poc1/poc2/...)


### Step 4: 消息推送

使用 Bark 、钉钉机器人、邮箱 发送通知

Service:
- [Brak](https://github.com/Finb/Bark)
- [Dingding](https://open.dingtalk.com/document/group/custom-robot-access)
- SMTP Email

消息推送相关配置修改：

1. 编辑 message.py 文件，自行添加 token 等信息
2. 编辑 listen.py 文件，自行选择启用 Bark/钉钉机器人/Email

```shell
## listen.py:10
# Message Send Service
Bark_msg_enabled = True
Ding_msg_enabled = False
Email_msg_enabled = False
```


## TODO

- [ ] 推送消息添加ASAN输出内容详情
- [ ] 调用GDB对其他crashes进行分析
- [ ] 使用 `afl-tmin` 最小化 crash 
- [ ] 自动生成 Issue 的提交信息
- [ ] 第一步的 `afl-fuzz` 改为自动执行
- [ ] 自动识别漏洞类型(CWE)
- [ ] 自动提交 CVE 申请 🤔
- [x] ~~添加邮件消息推送方式~~

## 最近更新内容

- 2022-11-2: 添加对collections内的crashes去重操作, 修复一些小bug