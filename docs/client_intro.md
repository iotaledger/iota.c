# Introduction

The C Client library is built for embedded development with microcontrollers. it can be ported to different operating system easily.

## IOTA Application Architecture

The real world application could be vary, here is an example architecture of an IOTA client application.

![](img/client_application_architecture.jpg)

## C Client Library Diagram

The C Client library relies on some functionalities:
* HTTP/HTTPS Client
* JSON parser
* Crypto library

Those features can be replace by system API or other library which provided by a platform.

![](img/client_block_diagram.jpg)

## Platform

It has ported to [ESP32](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/hw-reference/esp32/get-started-devkitc.html) and [B-L4S5I-IOT01A](https://www.st.com/en/evaluation-tools/b-l4s5i-iot01a.html), How-To articles are shown below:
* Writing an IOTA Client Application wit ESP32 on PlatformIO - TODO
* Writing an IOTA Client Application with STM32 B-L4S5I-IOT01A on mBed OS- TODO
