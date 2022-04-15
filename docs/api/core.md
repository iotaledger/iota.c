# Core API Reference

The Core API implemented objects, structures, utils for IOTA protocol.

It provides the following functionalities:

* Address derivation
* Message creations
* UTXO Input/Output operations
* Bech32, Slip10, uint256, and Byte Buffer utils

## Address

```{eval-rst}
.. doxygenenum:: address_type_t
  :members:
```

```{eval-rst}
.. doxygenstruct:: address_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: address_keypair_from_path
```

```{eval-rst}
.. doxygenfunction:: ed25519_address_from_path
```

```{eval-rst}
.. doxygenfunction:: alias_address_from_output
```

```{eval-rst}
.. doxygenfunction:: nft_address_from_output
```

```{eval-rst}
.. doxygenfunction:: address_len
```

```{eval-rst}
.. doxygenfunction:: address_serialized_len
```

```{eval-rst}
.. doxygenfunction:: address_serialize
```

```{eval-rst}
.. doxygenfunction:: address_deserialize
```

```{eval-rst}
.. doxygenfunction:: address_from_bech32
```

```{eval-rst}
.. doxygenfunction:: address_to_bech32
```

```{eval-rst}
.. doxygenfunction:: address_equal
```

```{eval-rst}
.. doxygenfunction:: address_clone
```

```{eval-rst}
.. doxygenfunction:: address_free
```

```{eval-rst}
.. doxygenfunction:: address_print
```

## Models

### Message

```{eval-rst}
.. doxygenenum:: core_message_payload_type_t
  :members:
```

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
.. doxygenfunction:: core_message_essence_hash_calc
```

```{eval-rst}
.. doxygenfunction:: core_message_add_parent
```

```{eval-rst}
.. doxygenfunction:: core_message_parent_len
```

```{eval-rst}
.. doxygenfunction:: core_message_get_parent_id
```

```{eval-rst}
.. doxygenfunction:: core_message_get_payload_type
```

```{eval-rst}
.. doxygenfunction:: core_message_serialize_len
```

```{eval-rst}
.. doxygenfunction:: core_message_serialize
```

```{eval-rst}
.. doxygenfunction:: core_message_print
```

### Signing

```{eval-rst}
.. doxygenstruct:: signing_data_t
  :members:
```

```{eval-rst}
.. doxygenstruct:: signing_data_list
  :members:
```

```{eval-rst}
.. doxygenfunction:: signing_new
```

```{eval-rst}
.. doxygenfunction:: signing_free
```

```{eval-rst}
.. doxygenfunction:: signing_data_add
```

```{eval-rst}
.. doxygenfunction:: signing_data_count
```

```{eval-rst}
.. doxygenfunction:: signing_get_data_by_index
```

```{eval-rst}
.. doxygenfunction:: signing_transaction_sign
```

### Unlock Blocks

```{eval-rst}
.. doxygenenum:: unlock_type_t
  :members:
```

```{eval-rst}
.. doxygenstruct:: unlock_block_t
  :members:
```

```{eval-rst}
.. doxygenstruct:: unlock_list
  :members:
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_add
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_add_signature
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_add_reference
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_add_alias
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_add_nft
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_count
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_get
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_find_pub
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_serialize_length
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_serialize
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_deserialize
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_free
```

```{eval-rst}
.. doxygenfunction:: unlock_blocks_print
```

### Inputs

```{eval-rst}
.. doxygenstruct:: utxo_input_t
  :members:
```

```{eval-rst}
.. doxygenstruct:: utxo_inputs_list
  :members:
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_new
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_free
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_add
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_count
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_find_by_id
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_find_by_index
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_serialize_len
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_serialize
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_deserialize
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_print
```

```{eval-rst}
.. doxygenfunction:: utxo_inputs_syntactic
```

### Outputs

```{eval-rst}
.. doxygenenum:: utxo_output_type_t
  :members:
```

```{eval-rst}
.. doxygenstruct:: utxo_output_t
  :members:
```


```{eval-rst}
.. doxygenstruct:: utxo_outputs_list
  :members:
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_new
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_free
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_add
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_count
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_get
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_serialize_len
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_serialize
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_deserialize
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_print
```

```{eval-rst}
.. doxygenfunction:: utxo_outputs_syntactic
```

### Payloads

#### Milestone

```{eval-rst}
.. doxygenstruct:: milestone_payload_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: milestone_payload_new
```

```{eval-rst}
.. doxygenfunction:: milestone_payload_free
```

```{eval-rst}
.. doxygenfunction:: milestone_payload_get_parents_count
```

```{eval-rst}
.. doxygenfunction:: milestone_payload_get_parent
```

```{eval-rst}
.. doxygenfunction:: milestone_payload_get_pub_keys_count
```

```{eval-rst}
.. doxygenfunction:: milestone_payload_get_pub_key
```

```{eval-rst}
.. doxygenfunction:: milestone_payload_get_signatures_count
```

```{eval-rst}
.. doxygenfunction:: milestone_payload_get_signature
```

```{eval-rst}
.. doxygenfunction:: milestone_payload_print
```

#### Tagged Data Payload

```{eval-rst}
.. doxygenstruct:: tagged_data_payload_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: tagged_data_new
```

```{eval-rst}
.. doxygenfunction:: tagged_data_free
```

```{eval-rst}
.. doxygenfunction:: tagged_data_serialize_len
```

```{eval-rst}
.. doxygenfunction:: tagged_data_serialize
```

```{eval-rst}
.. doxygenfunction:: tagged_data_deserialize
```

```{eval-rst}
.. doxygenfunction:: tagged_data_clone
```

```{eval-rst}
.. doxygenfunction:: tagged_data_print
```

#### Transaction Payload

##### Essence

```{eval-rst}
.. doxygenstruct:: transaction_essence_t
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
.. doxygenfunction:: tx_essence_inputs_commitment_calculate
```

```{eval-rst}
.. doxygenfunction:: tx_essence_serialize_length
```

```{eval-rst}
.. doxygenfunction:: tx_essence_serialize
```

```{eval-rst}
.. doxygenfunction:: tx_essence_deserialize
```

```{eval-rst}
.. doxygenfunction:: tx_essence_syntactic
```

```{eval-rst}
.. doxygenfunction:: tx_essence_print
```

##### Transaction

```{eval-rst}
.. doxygenstruct:: transaction_payload_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: tx_payload_new
```

```{eval-rst}
.. doxygenfunction:: tx_payload_free
```

```{eval-rst}
.. doxygenfunction:: tx_payload_serialize_length
```

```{eval-rst}
.. doxygenfunction:: tx_payload_serialize
```

```{eval-rst}
.. doxygenfunction:: tx_payload_deserialize
```

```{eval-rst}
.. doxygenfunction:: tx_payload_print
```

```{eval-rst}
.. doxygenfunction:: tx_payload_syntactic
```

## Utils

### uint256

```{eval-rst}
.. doxygenstruct:: uint256_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: uint256_from_str
```

```{eval-rst}
.. doxygenfunction:: uint256_add
```

```{eval-rst}
.. doxygenfunction:: uint256_sub
```

```{eval-rst}
.. doxygenfunction:: uint256_equal
```

```{eval-rst}
.. doxygenfunction:: uint256_to_str
```

```{eval-rst}
.. doxygenfunction:: uint256_clone
```

```{eval-rst}
.. doxygenfunction:: uint256_free
```

### Bech32

```{eval-rst}
.. doxygenfunction:: bech32_encode
```

```{eval-rst}
.. doxygenfunction:: bech32_decode
```

```{eval-rst}
.. doxygenfunction:: bech32_convert_bits
```

### Slip10

```{eval-rst}
.. doxygenstruct:: slip10_key_t
  :members:
```

```{eval-rst}
.. doxygenstruct:: bip32_path_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: slip10_parse_path
```

```{eval-rst}
.. doxygenfunction:: slip10_key_from_path
```

```{eval-rst}
.. doxygenfunction:: slip10_public_key
```


### Byte Buffer

```{eval-rst}
.. doxygenstruct:: byte_buf_t
  :members:
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
.. doxygenfunction:: byte_buf_print
```

```{eval-rst}
.. doxygenfunction:: byte_buf_str2hex
```

```{eval-rst}
.. doxygenfunction:: byte_buf_hex2str
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
.. doxygenfunction:: buf_all_zeros
```
