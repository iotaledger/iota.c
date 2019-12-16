# Contributing

Help is very welcome. Before making a Pull Request, ensure you have installed requirements and ran `./tools/hooks/autohook.sh install` after initial checkout!

## Requirements  

### [buildifier](https://github.com/bazelbuild/buildtools/tree/master/buildifier)  
Buildifier can be installed with `bazel` or `go`.  

**Install with go**  

1. change directory to `$GOPATH`
2. run `$ go get github.com/bazelbuild/buildtools/buildifier`
   The executable file will be located under `$GOPATH/bin`
3. create a soft link for global usage, run
   `$ sudo ln -s $HOME/go/bin/buildifier /usr/bin/buildifier`

**Install with bazel**  

1. clone `bazelbuild/buildtools` repository
   `$ git clone https://github.com/bazelbuild/buildtools.git`
2. change directory to `buildtools`
3. build it with bazel command, `$ bazel build //buildifier`
   The executable file will be located under `path/to/buildtools/bazel-bin`
4. create a soft link

### [clang-format](https://clang.llvm.org/docs/ClangFormat.html)  
clang-format can be installed by command:
- Debian/Ubuntu based: `$ sudo apt-get install clang-format`
- OSX: `$ brew install clang-format`
