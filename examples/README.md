# IOTA C Client Examples

This folder contains simple examples for developing IOTA client applications. 
For building example, please enable example option, `-DIOTA_EXAMPLES=TRUE`, during CMake configuration.

* node_info - getting node information from the connected node.
* data_message - sending `Hello World` to the Tangle and fetching it from the Tangle.
* encrypted_data - sending encrypted data to the Tangle and validating it.
* get_message - decoding message by a given message id 
* wallet_get_balance - getting wallet balance via wallet API.
* wallet_send_tx - sending tokens via wallet API.
* wallet_list_addresses - generating addresses via wallet API.
