# IOTA C Client Examples

This folder contains simple examples for developing IOTA client applications.
For building example, please enable example option, `-DIOTA_EXAMPLES=TRUE`, during CMake configuration.

* `arduino_esp32_info` - fetch node info with Arduino IDE
* `arduino_esp32_token_transfer` - transfer IOTA tokens with Arduino IDE
* Client - examples use client APIs
  * `encrypted_tagged_data_block` - sending encrypted data to the Tangle
  * `tagged_data_block` - sending data to the Tangle
  * `get_block` - getting Block object by a given BlockID
  * `node_info` - fetching node info from the connected node
  * `get_event_blocks` - subscript event by Even APIs
* Wallet - examples use wallet APIs
  * `create_alias_output` - Creating an Alias output
  * `int_native_tokens` - Minting a Native tokens
  * `send_basic_output` - Sending IOTA tokens to a receiver
  * `send_native_tokens` - Minting a Native tokens and send it to a receiver

