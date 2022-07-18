# Wallet API Reference

The Wallet API provides some helper methods for developers to create wallet alllications.

## Wallet Configuration

```{eval-rst}
.. doxygenstruct:: iota_wallet_t
  :members:
```

## Create and Destory Methods

```{eval-rst}
.. doxygenfunction:: wallet_create
```

```{eval-rst}
.. doxygenfunction:: wallet_destroy
```

```{eval-rst}
.. doxygenfunction:: wallet_set_endpoint
```

```{eval-rst}
.. doxygenfunction:: wallet_update_node_config
```

## Address Methods

```{eval-rst}
.. doxygenfunction:: wallet_ed25519_address_from_index
```

```{eval-rst}
.. doxygenfunction:: wallet_get_address_and_keypair_from_index
```

## UTXO Methods

```{eval-rst}
.. doxygenfunction:: wallet_is_collected_balance_sufficient
```

```{eval-rst}
.. doxygenfunction:: wallet_calculate_remainder_amount
```

```{eval-rst}
.. doxygenfunction:: wallet_send
```

```{eval-rst}
.. doxygenfunction:: wallet_create_core_block
```

```{eval-rst}
.. doxygenfunction:: wallet_send_block
```

```{eval-rst}
.. doxygenfunction:: wallet_alias_output_create
```

```{eval-rst}
.. doxygenfunction:: wallet_alias_output_state_transition
```

```{eval-rst}
.. doxygenfunction:: wallet_alias_output_destroy
```

```{eval-rst}
.. doxygenfunction:: wallet_basic_output_create
```

```{eval-rst}
.. doxygenfunction:: wallet_get_unspent_basic_output_ids
```

```{eval-rst}
.. doxygenfunction:: wallet_basic_output_send
```

```{eval-rst}
.. doxygenfunction:: wallet_foundry_output_mint_native_tokens
```

## Mnemonic Sentence

```{eval-rst}
.. doxygenenum:: ms_lan_t
```

```{eval-rst}
.. doxygenenum:: ms_entropy_t
```

```{eval-rst}
.. doxygenfunction:: mnemonic_to_seed
```

```{eval-rst}
.. doxygenfunction:: mnemonic_generator
```

```{eval-rst}
.. doxygenfunction:: mnemonic_encode
```

```{eval-rst}
.. doxygenfunction:: mnemonic_decode
```

```{eval-rst}
.. doxygenfunction:: mnemonic_convertor
```

```{eval-rst}
.. doxygenfunction:: mnemonic_validation
```
