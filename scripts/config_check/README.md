# wolfSSL Configuration Assistance

This directory contains an utility script called [refresh.sh](./refresh.sh) that reads a bash-like command in [cmd.txt](./cmd.txt) 
and runs it. 

The command expected is the wolfSSL `./configure` that expects a potentially _large_ number of parameters. (see `./configure --help` 
and the [build documentation](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html)). 

Unlike normal bash commands spanning multiple lines, comments are allowed. Use the same `#` on a line for everything afterwards to be ignored. 

Line continuation characters `\` are ignored in the command [cmd.txt](./cmd.txt) file. 

Blank lines will be ignored and do not need line continuation characters in the command [cmd.txt](./cmd.txt) file.

Embedded comments with the `#` character are supported and can be used for your own personal comments
regarding each of the options enabled or disabled.

The multi-line `./configure` command with all parameters on subsequent lines is stripped of comments and everything placed on a single line statement when executed.

Upon execution, the entire output is set to a file called [output.txt](./output.txt). Additionally, the enabled/disabled features (those items with an asterisk in the output and the word "yes" or "no") 
are separated and stored in the respective [Enabled-Features.txt](./Enabled-Features.txt) and [Disabled-Features.txt](./Disabled-Features.txt) files.

## Purpose

This script may help in a variety of ways:

- Observe which options have side-effects that may enable other options.
- Determine which `--option-setting` causes a specific `#define` to be enabled (helpful for embedded developers).
- Record specific project settings of enabled and disabled features.

## Installation

There's no need to install this script, as it can be run from the wolfSSL `./scripts/config_check` directory as noted in the Usage section, below.

If you'd like to run from a someplace else, place the  [refresh.sh](./refresh.sh) and [cmd.txt](./cmd.txt) files in a directory and
edit the respective `refresh.sh` file. The first `cd "../.."` command will need to be edited to change to your wolfssl directory 
to run the `./configure` command. See the [Configuration](https://github.com/gojimmypi/wolfssl/tree/ConfigCheck/scripts/config_check#configuration) section, below.

It may be convenient for the command and output files to be in a included in GitHub fork repo for 
easily tracking changes to the output files, typically your project that is using wolfSSL.

## Configuration

See the variables in the [refresh.sh](./refresh.sh) script:

Note in particular the environment variables:

```
WOLFSSL_REPO="$PWD"
WOLFSSL_FILE_ROOT="$WOLFSSL_REPO/scripts/config_check"
```
If you'd like to save the results someplace else, the file output locations are set like this:

```
WOLFSSL_OUTPUT="$WOLFSSL_FILE_ROOT/output.txt"
WOLFSSL_OPTIONS="$WOLFSSL_FILE_ROOT/options.h"
WOLFSSL_YES="$WOLFSSL_FILE_ROOT/Enabled-Features.txt"
WOLFSSL_NO="$WOLFSSL_FILE_ROOT/Disabled-Features.txt"
```

Edit those locations to suit your needs. See below for more details:

#### `WOLFSSL_REPO` 

This is the location of wolfSSL where the `./configure` script should run and is typically the location of your wolfSSL `git clone`. 
For example in WSL for a clone command from the `C:\workspace` directory, this value would be:

`WOLFSSL_REPO="/mnt/c/workspace/wolfssl"`

#### `WOLFSSL_FILE_ROOT`

The directory where `./configure` console output will be saved in various files (a github repo is helpful for tracking changes). 
For example, you could choose to redirect to a different location:

`WOLFSSL_FILE_ROOT="~/myproject/_debug"`


#### `WOLFSSL_CMD_FILE`

This is the `./configure` command to edit. This is typically the location of the [cmd.txt](./cmd.txt) file
located in the same `WOLFSSL_FILE_ROOT` directory.

`WOLFSSL_CMD_FILE="$WOLFSSL_FILE_ROOT/cmd.txt"`


#### Output files

The output files currently all go to the `$WOLFSSL_FILE_ROOT` but can be adjusted as needed:

```
WOLFSSL_OUTPUT="$WOLFSSL_FILE_ROOT/output.txt"
WOLFSSL_OPTIONS="$WOLFSSL_FILE_ROOT/options.h"
WOLFSSL_YES="$WOLFSSL_FILE_ROOT/Enabled-Features.txt"
WOLFSSL_NO="$WOLFSSL_FILE_ROOT/Disabled-Features.txt"
```

These files are all included in the GitHub `.ignore` file in the root of the repository. 
Edit that file or redirect the output to a different location if you'd like to track changes.

Note that a fresh `help.txt` file will be generated each time this script runs. 
If you are tracking this in your own repo, you can readily see what new features may have been 
added since last used.

## Usage

Run the `./refresh.sh` command from the `wolfssl/scripts/config_check` directory:

```
cd wolfssl/scripts/config_check
./refresh.sh
```

Observe the generated output text files and `options.h`.



## Other Resources

- [Building wolfSSL](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html)
- Kaleb's [wolfSoFT - wolf Suite of Frameworks and Tools](https://github.com/kaleb-himes/wolfSoFT)

* Note Kaleb is working on a "user settings to configure file" feature to create a wolfSSL `.configure` command with the parameters used to create the provided header file.