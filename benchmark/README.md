# Memory Benchmark for IOTA C Client Library

## About

When talking about memory usage of a program, we usually distinguish between **non-volatile** (eg. disk/flash) and
**volatile** (eg. SRAM/DRAM) types of a memory because typical program uses both to perform any given task.

This folder contains a memory benchmark tools for IOTA C Client Library for both types of a memory.

Memory benchmark can be done for a following library modules:
- Crypto
- Core
- Client
- Wallet

and some demo applications:
- `create_transaction_basic_output` (Transaction with one input and one basic output without native tokens or feature blocks.)
- `create_transaction_basic_output_full` (Transaction with one input and one basic output with one native token and all possible feature blocks.)
- `create_transaction_basic_output_max` (Transaction with maximum number of inputs, outputs and number of native tokens. Each basic output has all possible feature blocks.)
- `send_tagged_data` (With Client module a tagged data is sent to a tangle.)
- `send_tagged_data_max` (With Client module a tagged data with maximum length of tag and data is sent to a tangle.)

Demo applications are in `core` and `client` folders.

## Prerequisites

* [Python 3](https://www.python.org)
* [Valgrind](https://valgrind.org)
* [Bloaty](https://github.com/google/bloaty)
* [size](https://man7.org/linux/man-pages/man1/size.1.html)

To compile and build all library modules and demo applications for a Release build using GCC compiler and libsodium crypto library we need to execute:

```shell
git clone https://github.com/iotaledger/iota.c.git
cd iota.c
mkdir build && cd build
cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Release -DIOTA_BENCHMARK=TRUE -DIOTA_WALLET_ENABLE=TRUE -DCryptoUse=libsodium -DCMAKE_INSTALL_PREFIX=$PWD ..
make -j8
```

## Binary Artifact Size

In this section we will focus on a **non-volatile** memory and measure a size of different build artifacts (static
library or executable file) which a compiler will produce.

### Benchmarking Binary Size of Modules

To get a binary size of a produced archive library file (.a file extension) we need to execute:
```shell
size -t libiota_*.a
```
for each archive library file or demo application separately.

---

Example for `Core` module if we are in `build` directory:
```shell
size -t ./src/core/libiota_core.a
```

### Benchmarking Binary Size of Modules by Their Sections

A typical memory representation of a C program consists of the following sections:
- `.text`: Program code (read only).
- `.rodata`: Constants (const modifier) and strings (read only). The .rodata section is usually merged with .text section and put into the executable section.
- `.data`: Initialized global and static variables (startup value ≠ 0).
- `.bss`: Uninitialized global and static variables (zero value on startup).

To get a binary size by sections of a produced archive library file (*.a file extension*) or a demo application we need to execute:
```shell
bloaty -d sections libiota_*.a
or
bloaty -d sections demo_application_file
```
for each archive library file or demo application separately.

---

Example for `create_transaction_basic_output` demo application if we are in `build` directory:
```shell
bloaty -d sections ./benchmark/benchmark_create_transaction_basic_output
```

## RAM Memory Consuption

In this section we will focus on a **volatile** memory (RAM) and measure its usage during runtime of a demo
applications which uses IOTA C Client Library.

### Measuring a Peak of a Heap Size

To get a peak of a heap size during runtime of a demo application we need to execute:
```shell
./run_benchmark.sh demo_application_file
```
for each demo application separately.

---

Example for `send_tagged_data` demo application if we are in `build` directory:
```shell
../benchmark/run_benchmark.sh ./benchmark/benchmark_send_tagged_data
```

### Measuring a Memory Allocations on a Heap

To get number and size of a memory allocations on a heap during runtime of a demo application we need to add a following flag to CMake options:
```shell
-DENABLE_MTRACE=TRUE
```
and execute:
```shell
python measure_heap_consumers.py demo_application_file
```
for each demo application separately.

---

Example for `create_transaction_basic_output_full` demo application if we are in `build` directory:
```shell
python ../benchmark/measure_heap_consumers.py ./benchmark/benchmark_create_transaction_basic_output_full
```
