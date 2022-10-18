
# LazyCrasher

AFL input & output folders path:

```shell
AFL_Fuzz_Datas
├── vim
│   ├── input
│   ├── output
│       ├── fuzzer01
│           ├── crashes
│       ├── fuzzer02
│   ├── collections
│       ├── README.txt
├── gpac
│   ├── input
│   ├── output
```


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

Example:

```shell
$ python3 listen.py -d Datas -l 1 -t 20 -v
```


## Run

Add to the crontab


## Process

### Step 1: Start the AFL fuzzer (By yourself)

```shell
$ afl-fuzz -M fuzzer01 -i <AFL_Fuzz_Datas>/<Project_name>/input -o <AFL_Fuzz_Datas>/<Project_name>/output -- <target> --target-opts
$ afl-fuzz -S fuzzer02 -i <AFL_Fuzz_Datas>/<Project_name>/input -o <AFL_Fuzz_Datas>/<Project_name>/output -- <target> --target-opts
```

Notice:

- Use absolute path args to run `afl-fuzz`

### Step 2: Listen crashes output

Path: `<AFL_Fuzz_Datas>/<Project_name>/output/<fuzzer01>/crashes/`


### Step 3: Invoke afl-collect (if available)

```shell
$ afl-collect -j 8 -e gdb_script -r -rr -i <AFL_Fuzz_Datas>/<Project_name>/output -o <AFL_Fuzz_Datas>/<Project_name>/collections -- <target> --target-opts
```


### Step 4: Send message 

Service:
- Brak
- Dingding


## TODO

1. Use afl-tmin to minimize the crashes
2. Auto generate the Issue's Markdown file by using the template.
3. Auto run the `afl-fuzz`