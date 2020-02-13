# binary-cookie-extractor
A Go based program that extracts/decodes Safari/iOS/iPadOS binary cookie files

Requires Go and runs on macOS, Windows, and Linux. Created by me, KittyNighthawk (https://github.com/KittyNighthawk)

## Installation
To install binary-cookie-extract, first ensure the following dependencies are met:
- Go is installed (available at https://golang.org for macOS, Windows, and Linux)
- Git is installed (available at https://git-scm.com)

Once Go and Git are installed, run:

```
$ go get github.com/KittyNighthawk/binary-cookie-extractor
```

This will download the program from GitHub, build it, and install it.

To make sure you can run Go binaries from the command line, ensure that the $GOPATH is in your %PATH environment variable. For example:

```
$ export PATH=$PATH:/usr/local/go/bin
```

Further details on Go installation and setup can be found at https://golang.org/doc/install

## Usage
This is a command line tool. In it's simplest form you only need to provide the path to the binary cookies file to the -i option, for example:

```
$ ./binary-cookie-extractor -i Cookies.binarycookies
```

You can get a list of options with:

```
$ ./binary-cookie-extractor -h
```

Below is a list of all current options:
- ```-i``` - Provide the path to the binary cookies file
- ```-f``` - Specify the format. Current options are table (default) and list
- ```-d``` - Enabled debugging output
- ```-v``` - Print out the version information

## Format of Binary Cookie Files
To help other understand the binary cookies file format used by Apple device, here is a breakdown of them, including a byte map.

[TBC]
