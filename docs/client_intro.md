# Introduction

The C Client library is built for embedded development with microcontrollers and SoC(System on Chip). it can be ported to POSIX operating systems easily.

Software Development Kits(SDK) for MCUs:
* [esp32-client-sdk](https://github.com/iotaledger/esp32-client-sdk) - based on ESP-IDF for ESP32 series
* [zephyr-client-sdk](https://github.com/iotaledger/zephyr-client-sdk) - based on ZephyrOS, supports hundreds of MCU out of the box, it works with nRF Connect SDK for Nordic microcontrollers as well.
* [iota-mbed-studio](https://github.com/iotaledger/iota-mbed-studio) - based on ARM Mbed OS and [Mbed Studio IDE](https://os.mbed.com/studio/).

## C Client Library Diagram

The C Client library consists 4 abstraction layers:
* Crypto - provide cryptographic functions
* Core - implement components include address/message/UTXO...
* Client - implement node REST APIs and Event APIs. (optional)
* Wallet - simple wallet functions. (optional)

As a client application, Client and Wallet modules could be an option as needed. For instance, the application can implement its own wallet logic or it uses the Core module to compose messages then send messages through another interface without the Client module.

![](img/client_block_diagram.jpg)

The C Client library relies on some functionalities from the operating system API or external library:
* HTTP/HTTPS Client
* JSON parser
* Crypto library
* MQTT Client

## IOTA Application Architecture

The real world application could be vary, here is an example architecture of an IOTA client application.

With the client library, you can interact with IOTA Tangle to:
* Create data and transaction messages
* Send data and transaction messages
* Query messages
* Query the node status
* Generate addresses
* Subscribe node events

![](img/client_application_architecture.jpg)
