# IOTA C Client Examples

This folder contains simple examples for developing IOTA client applications. 
For building example, please enable example option, `-DIOTA_EXAMPLES=TRUE`, during CMake configuration.

* node_info - getting node information from a connected node.
* tagged_data_message - sending `Hello world` to the Tangle and then fetching it from the Tangle.
* encrypted_tagged_data_message - sending encrypted data to the Tangle and then fetching and validating it.
* get_message - fetching and decoding Milestone, Tagged Data or Transaction message by a given message ID 
* send_basic_output - sending tokens via wallet API.
