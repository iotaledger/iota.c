# Functional Test Application
 
The `functional-tests` is an application which test the functionality of iota.c by interacting with the IOTA network.

# Usage

Make sure `IOTA_TESTS` and `IOTA_WALLET_ENABLE` is enabled during CMake config, for example:

```
git clone https://github.com/iotaledger/iota.c.git
cd iota.c
mkdir build && cd build
cmake -DIOTA_TESTS=TRUE -DIOTA_WALLET_ENABLE=TRUE -DCryptoUse=libsodium -DCMAKE_INSTALL_PREFIX=$PWD ..
make -j8
```

After build wihtout problems the application is in `build/functional-tests` folder.

```
cd functional-tests
./functional-tests ./config.json
```

