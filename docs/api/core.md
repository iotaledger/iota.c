# Core API Reference

The Core API is low level API implementation based on [iotaledger/protocol-rfcs](https://github.com/iotaledger/protocol-rfcs/pulls), it helps to process message easily with following key functions:
* Address conversion
* Message operations
* Input/Output operations
* Common utilities(bech32, slip10)

## [Address](https://github.com/iotaledger/iota.c/blob/dev/src/core/address.h)

```{eval-rst}
.. doxygenfunction:: address_from_ed25519_pub
```

```{eval-rst}
.. doxygenfunction:: address_keypair_from_path
```

```{eval-rst}
.. doxygenfunction:: address_from_path
```

```{eval-rst}
.. doxygenfunction:: address_from_bech32
```

```{eval-rst}
.. doxygenfunction:: address_2_bech32
```

```{eval-rst}
.. doxygenfunction:: address_bech32_to_hex
```

## [Message](https://github.com/iotaledger/iota.c/blob/dev/src/core/models/message.h)

```{eval-rst}
.. doxygenstruct:: core_message_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: core_message_new
```

```{eval-rst}
.. doxygenfunction:: core_message_free
```

```{eval-rst}
.. doxygenfunction:: core_message_sign_transaction
```

```{eval-rst}
.. doxygenfunction:: core_message_add_parent
```

```{eval-rst}
.. doxygenfunction:: core_message_parent_len
```

## [Indexation Payload](https://github.com/iotaledger/iota.c/blob/dev/src/core/models/payloads/indexation.h)

```{eval-rst}
.. doxygenstruct:: indexation_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: indexation_new
```

```{eval-rst}
.. doxygenfunction:: indexation_free
```

```{eval-rst}
.. doxygenfunction:: indexation_create
```

## [Transaction Payload](https://github.com/iotaledger/iota.c/blob/dev/src/core/models/payloads/transaction.h)

```{eval-rst}
.. doxygenstruct:: ed25519_signature_t
  :members:
```

### Transaction Essence

```{eval-rst}
.. doxygenstruct:: transaction_essence_t
  :members:
```

```{eval-rst}
.. doxygenstruct:: unlock_blocks
  :members:
```

```{eval-rst}
.. doxygenfunction:: tx_essence_new
```

```{eval-rst}
.. doxygenfunction:: tx_essence_free
```

```{eval-rst}
.. doxygenfunction:: tx_essence_add_input
```

```{eval-rst}
.. doxygenfunction:: tx_essence_add_output
```

```{eval-rst}
.. doxygenfunction:: tx_essence_add_payload
```

```{eval-rst}
.. doxygenfunction:: tx_essence_print
```

```{eval-rst}
.. doxygenfunction:: tx_blocks_new
```

```{eval-rst}
.. doxygenfunction:: tx_blocks_free
```

```{eval-rst}
.. doxygenfunction:: tx_blocks_add_signature
```

```{eval-rst}
.. doxygenfunction:: tx_blocks_add_reference
```

```{eval-rst}
.. doxygenfunction:: tx_blocks_count
```

```{eval-rst}
.. doxygenfunction:: tx_blocks_print
```

### Transaction Payload

```{eval-rst}
.. doxygenstruct:: transaction_payload_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: tx_payload_new
```

```{eval-rst}
.. doxygenfunction:: tx_payload_add_input
```

```{eval-rst}
.. doxygenfunction:: tx_payload_add_input_with_key
```

```{eval-rst}
.. doxygenfunction:: tx_payload_add_output
```

```{eval-rst}
.. doxygenfunction:: tx_payload_add_sig_block
```

```{eval-rst}
.. doxygenfunction:: tx_payload_add_ref_block
```

```{eval-rst}
.. doxygenfunction:: tx_payload_print
```

## [Outputs](https://github.com/iotaledger/iota.c/blob/dev/src/core/models/outputs/outputs.h)

```{eval-rst}
.. doxygenstruct:: outputs_ht
  :members:
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_new
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_free
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_print
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_add
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_find_by_addr
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_count
```

## [Inputs](https://github.com/iotaledger/iota.c/blob/dev/src/core/models/inputs/utxo_input.h)

```{eval-rst}
.. doxygenstruct:: ed25519_keypair_t
  :members:
```

```{eval-rst}
.. doxygenstruct:: utxo_input_ht
  :members:
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_new
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_free
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_print
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_add
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_add_with_key
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_count
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_find_by_id
```

## [Utils](https://github.com/iotaledger/iota.c/tree/dev/src/core/utils)

### [Bech32](https://github.com/iotaledger/iota.c/blob/dev/src/core/utils/bech32.h)

```{eval-rst}
.. doxygenfunction:: iota_addr_bech32_encode
```

```{eval-rst}
.. doxygenfunction:: iota_addr_bech32_decode
```

### [Slip10](https://github.com/iotaledger/iota.c/blob/dev/src/core/utils/slip10.h)

```{eval-rst}
.. doxygenfunction:: slip10_key_from_path
```

```{eval-rst}
.. doxygenfunction:: slip10_public_key
```


### [Byte Buffer](https://github.com/iotaledger/iota.c/blob/dev/src/core/utils/byte_buffer.h)

```{eval-rst}
.. doxygenstruct:: byte_buf_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: hex2string
```

```{eval-rst}
.. doxygenfunction:: string2hex
```

```{eval-rst}
.. doxygenfunction:: hex_2_bin
```

```{eval-rst}
.. doxygenfunction:: bin_2_hex
```

```{eval-rst}
.. doxygenfunction:: byte_buf_new
```

```{eval-rst}
.. doxygenfunction:: byte_buf_free
```

```{eval-rst}
.. doxygenfunction:: byte_buf_new_with_data
```

```{eval-rst}
.. doxygenfunction:: byte_buf_append
```

```{eval-rst}
.. doxygenfunction:: byte_buf_set
```

```{eval-rst}
.. doxygenfunction:: byte_buf2str
```

```{eval-rst}
.. doxygenfunction:: byte_buf_clonen
```

```{eval-rst}
.. doxygenfunction:: byte_buf_clone
```

```{eval-rst}
.. doxygenfunction:: byte_buf_reserve
```

```{eval-rst}
.. doxygenfunction:: byte_buf_str2hex
```

```{eval-rst}
.. doxygenfunction:: byte_buf_hex2str
```

```{eval-rst}
.. doxygenfunction:: byte_buf_print
```
