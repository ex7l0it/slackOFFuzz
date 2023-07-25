
# LazyCrasher

## 简介

一个自动检测 AFL crashes 输出的脚本，可自动启动afl-fuzz，可以添加定时任务执行，自动检测 crashes 文件夹中是否有新的崩溃产生并发送通知。如果已经安装 afl-utils，可自动调用 afl-collect 以进一步处理crashes。

## 依赖环境安装

```shell
sudo apt update && sudo apt install tmux python3 python3-pip -y
pip3 install -r requirements.txt
```

> 测试服务器系统版本：Ubuntu 20.04
> 已安装 AFL++


## 使用说明

```shell
✗ python3 lazycrasher.py --help           
usage: lazycrasher.py [-h] [-a ADD_TASK] [-r RUN] [-t TIME] [-s SOFTWARE] [-l LOG_LEVEL] [-v]

Lazycrasher opts

optional arguments:
  -h, --help            show this help message and exit
  -a ADD_TASK, --add-task ADD_TASK
                        Add a new fuzz project task
  -r RUN, --run RUN     Run a fuzz project task
  -t TIME, --time TIME  Set the time from the current time when the search crash occurs
  -s SOFTWARE, --software SOFTWARE
                        Software to search for fuzz projects, Default: None (Search All fuzz projects)
  -l LOG_LEVEL, --log-level LOG_LEVEL
                        Level of Sending message: [0] Send message when find new crashes(not collect) [Default] | [1] Send message when find useful crashes (after collect)
  -v, --verbose         Show all debug messages
```


## 操作流程

### Step 1. 下载目标库源码，手动进行编译

```shell
export CFLAGS="-fsanitize=address"
export CXXFLAGS="-fsanitize=address"
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_USE_ASAN=1
```

### Step 2. 运行脚本，创建一个任务文件夹 (以gpac为例)

- 这里要输入的绝对路径加参数信息就是 afl-fuzz 命令 -- 后面的那一部分

```shell
$ python3 lazycrasher.py -a gpac 
 [+]  Please input the fuzz target program absolute path with args:
/home/fuzz/FuzzProjects/202307/gpac/bin/gcc/MP4Box -info @@
 [+]  Add task gpac successfully! Please add the fuzz input to /home/fuzz/slackOFFuzz/tasks/gpac/input
```

### Step 3. 将种子放到刚刚打印出来的input目录下

```shell
mv poc /home/fuzz/slackOFFuzz/tasks/gpac/input
```

### Step 4. 运行脚本，开始fuzz

```shell
$ python3 lazycrasher.py -r gpac
 [+]  Start fuzzing..., Please use `tmux a -t fuzz_gpac` to attach the tmux session.
```

### Step 5. 命令行进入 tmux 会话，查看任务执行情况

```shell
tmux a -t fuzz_gpac
```

### Step 6. 开启 crontab 计划任务进行监听

如果没有问题，那么可以 Ctrl+b d 退出 tmux 会话，开启 crontab 计划任务进行监听，当发现有新的 crash 出现时发送通知

```shell
$ crontab -e
# 7-22点之间每隔两个小时执行一次脚本
0 7-22/2 * * * /home/fuzz/slackOFFuzz/start.sh 120
```

> 说明一下: 定时任务在添加后不会立即执行, 而是根据配置的时间去间隔执行, 所以检测crashes也不是实时的

## 其他

AFL input & output 文件夹结构:

```shell
AFL_Fuzz_Datas(tasks)
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

## 脚本工作流程

### Step 1: 创建任务并运行

会在指定的 FuzzProjectDataPath 目录下创建任务文件夹，当用户将种子传入指定的input文件夹后，脚本可通过在 tmux 中创建 afl 任务启动 fuzz (采用并行模式, 创建三个afl-fuzz进程)

### Step 2: 运行该脚本用于监听crashes文件夹

crashes 路径: `<AFL_Fuzz_Datas>/<Project_name>/output/<fuzzer01>/crashes/`

脚本执行后，它将会扫描 crashes 目录，当检测到有新的 crash 产生时进行下一步操作

### Step 3: 调用 afl-collect (如果可用)

如果 `afl-collect` 可用 (已安装 [afl-utils](https://gitlab.com/rc0r/afl-utils) ), 那么执行 `afl-collect` 用于收集和处理crashes

将会执行以下命令:

```shell
$ afl-collect -j 8 -e gdb_script -r -rr <AFL_Fuzz_Datas>/<Project_name>/output <AFL_Fuzz_Datas>/<Project_name>/collections -- <target> --target-opts
```

> 注意: 这里是写死了用 8 个核心去跑的

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
2. 编辑 lazycrasher.py 文件，自行选择启用 Bark/钉钉机器人/Email

```shell
## lazycrasher.py:13
# Message Send Service
Bark_msg_enabled = True
Ding_msg_enabled = False
Email_msg_enabled = False
```


## TODO

- [ ] 改用 logging 打印日志
- [ ] 推送消息添加ASAN输出内容详情
- [ ] 调用GDB对其他crashes进行分析
- [ ] 使用 `afl-tmin` 最小化 crash 
- [ ] 自动生成 Issue 的提交信息
- [ ] 自动识别漏洞类型(CWE)

## 最近更新内容

- 2023-07-25: 能够继续执行停止的fuzz任务
- 2023-07-19: 修复先前collect的poc会被删掉的bug
- 2023-07-15: 改为自动调用afl-fuzz，且保存到tmux会话
- 2022-11-02: 添加对collections内的crashes去重操作, 修复一些小bug