# RESTful API Reference

The RESTful APIs are low level client implementations based on 
- [TIP-25 Node Core REST API](https://github.com/iotaledger/tips/pull/57)
- [TIP-26 UTXO Indexer REST API](https://github.com/iotaledger/tips/pull/62)

Used to communicate with the Tangle network through the Node.

## Node

### Endpoint Setting

```{eval-rst}
.. doxygenstruct:: iota_client_conf_t
  :members:
```

### Error Response

```{eval-rst}
.. doxygenstruct:: res_err_t
  :members:
```

### `/health`

Returns the health of the node. A node considers itself healthy if its solid milestone is at most two delta away from the latest known milestone, has at least one ongoing gossip stream and the latest known milestone is newer than 5 minutes. This information might be useful for load-balancing or uptime monitoring.


```{eval-rst}
.. doxygenfunction:: get_health
```

### `/api/v2/info`

Returns general information about the node.

```{eval-rst}
.. doxygenstruct:: get_node_info_t
```

```{eval-rst}
.. doxygenstruct:: res_node_info_t
```

```{eval-rst}
.. doxygenfunction:: get_node_info
```

## Tangle

### `/api/v2/tips`

Returns tips that are ideal for attaching a block. The tips can be considered as `non-lazy` and are therefore ideal for attaching a block.

```{eval-rst}
.. doxygenstruct:: res_tips_t
```

```{eval-rst}
.. doxygenfunction:: get_tips
```

## Blocks

### `/api/v2/blocks`

Submit a block. The node takes care of missing fields and tries to build the block. On success, the block will be stored in the Tangle. This endpoint will return the identifier of the built block. The node will try to auto-fill the following fields in case they are missing: `protocolVersion`, `parents`, `nonce`. If `payload` is missing, the block will be built without a payload.


```{eval-rst}
.. doxygenstruct:: res_send_block_t
```

```{eval-rst}
.. doxygenfunction:: send_core_block
```

### `/api/v2/blocks/{blockId}`

Find a block by its identifier.

```{eval-rst}
.. doxygenstruct:: res_block_t
```

```{eval-rst}
.. doxygenfunction:: get_block_by_id
```

### `/api/v2/blocks/{blockId}/metadata`

Find the metadata of a given block ID.

```{eval-rst}
.. doxygenstruct:: block_meta_t
```

```{eval-rst}
.. doxygenstruct:: res_block_meta_t
```

```{eval-rst}
.. doxygenfunction:: get_block_metadata
```

## UTXO

### `/api/v2/outputs/{outputId}`

Find an output data by its identifier.

```{eval-rst}
.. doxygenstruct:: get_output_t
```

```{eval-rst}
.. doxygenstruct:: res_output_t
```

```{eval-rst}
.. doxygenfunction:: get_output
```

### `/api/v2/transaction/{transactionId}/included-block`

Returns the included block of a transaction.

```{eval-rst}
.. doxygenfunction:: get_transaction_included_block_by_id
```

## UTXO Indexer

### query parameters

```{eval-rst}
.. doxygenenum:: outputs_query_params_e
```

```{eval-rst}
.. doxygenstruct:: outputs_query_params_t
```

```{eval-rst}
.. doxygenstruct:: outputs_query_list
```

```{eval-rst}
.. doxygenfunction:: outputs_query_list_new
```

```{eval-rst}
.. doxygenfunction:: outputs_query_list_add
```

```{eval-rst}
.. doxygenfunction:: get_outputs_query_str_len
```

```{eval-rst}
.. doxygenfunction:: get_outputs_query_str
```

```{eval-rst}
.. doxygenfunction:: outputs_query_list_free
```

### Indexer Response

```{eval-rst}
.. doxygenstruct:: get_outputs_id_t
```

```{eval-rst}
.. doxygenstruct:: res_outputs_id_t
```

### `/api/plugins/indexer/v1/outputs/basic`

Returns Basic outputs filtered based on parameters.

```{eval-rst}
.. doxygenfunction:: get_basic_outputs
```

### `/api/plugins/indexer/v1/outputs/alias`

Returns Alias outputs filtered based on parameters.

```{eval-rst}
.. doxygenfunction:: get_alias_outputs
```

### `/api/plugins/indexer/v1/outputs/alias/{aliasId}`

Returns the output ID of the current unspent Alias output for Alias ID.

```{eval-rst}
.. doxygenfunction:: get_outputs_from_alias_id
```

### `/api/plugins/indexer/v1/outputs/foundry`

Returns Foundry outputs filtered based on parameters.

```{eval-rst}
.. doxygenfunction:: get_foundry_outputs
```

### `/api/plugins/indexer/v1/outputs/foundry/{foundryId}`

Returns the output ID of the current unspent foundry output for Foundry Id

```{eval-rst}
.. doxygenfunction:: get_outputs_from_foundry_id
```

### `/api/plugins/indexer/v1/outputs/nft`

Returns NFT outputs filtered based on parameters

```{eval-rst}
.. doxygenfunction:: get_nft_outputs
```

### `/api/plugins/indexer/v1/outputs/nft/{nftId}`

Returns the output ID of the current unspent NFT output for NFT ID.

```{eval-rst}
.. doxygenfunction:: get_outputs_from_nft_id
```
