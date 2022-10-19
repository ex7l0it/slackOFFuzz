
# LazyCrasher

## Description

A script to automatically detect the output of AFL crashes, with the ability to add timed tasks to automatically retrieve whether new crashes are generated in the crashes folder and send notifications. If afl-utils is available, afl-collect can be called automatically for further filtering of crashes.


## Usage

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


## Run

Manual execution:

```shell
$ python3 listen.py -d Datas -l 1 -t 20 -v
```

Auto execution: Add to the crontab

```
start.sh arg1 (arg1 is `--time` to run the listen.py)
* */1 * * * <path>/start.sh > /tmp/log.txt
```

## Process

### Step 1: Start the AFL fuzzer (By yourself)

```shell
$ afl-fuzz -M fuzzer01 -i <AFL_Fuzz_Datas_Path>/<Project_name>/input -o <AFL_Fuzz_Datas>/<Project_name>/output -- <target> --target-opts
$ afl-fuzz -S fuzzer02 -i <AFL_Fuzz_Datas_Path>/<Project_name>/input -o <AFL_Fuzz_Datas>/<Project_name>/output -- <target> --target-opts
```

Notice:

- Use absolute path args to run `afl-fuzz`


AFL input & output Folder structure:

```shell
AFL_Fuzz_Datas
├── vim
│   ├── input
│   ├── output
│       ├── fuzzer01
│           ├── crashes
│       ├── fuzzer02
│   ├── collections
│       ├── README.txt (copy from fuzzer*/README.txt)
├── gpac
│   ├── input
│   ├── output
```

### Step 2: Run this Script to Listen crashes output

crashes Path: `<AFL_Fuzz_Datas>/<Project_name>/output/<fuzzer01>/crashes/`

After the script is executed, the crashes directory will be scanned to find whether there are new files within the specified time. If there are new files, the next step will be taken

### Step 3: Invoke afl-collect (if available)

If `afl-collect` is available (installed [afl-utils](https://gitlab.com/rc0r/afl-utils) ), then `afl-collect` will be invoked to collect and process the crashes.

Will execute this command:

```shell
$ afl-collect -j 8 -e gdb_script -r -rr <AFL_Fuzz_Datas>/<Project_name>/output <AFL_Fuzz_Datas>/<Project_name>/collections -- <target> --target-opts
```


### Step 4: Send message 

The processed result message will be sent via Brak or Dingding

Service:
- [Brak](https://github.com/Finb/Bark)
- [Dingding](https://open.dingtalk.com/document/group/custom-robot-access)

## TODO

1. Use `afl-tmin` to minimize the crashes
2. Auto generate the Issue's Markdown file by using the template.
3. Auto run the `afl-fuzz`
4. Auto submit CVE requests