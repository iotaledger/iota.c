# Client API Reference

The Client API is low level client implementation based on [RFC: REST Node API](https://github.com/iotaledger/protocol-rfcs/pull/27), it enables communications with the Node on the Tangle.

## [Endpoint Setting](https://github.com/iotaledger/iota.c/blob/dev/src/client/client_service.h)

```{eval-rst}
.. doxygenstruct:: iota_client_conf_t
  :members:
```

## [Error Response](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/v1/response_error.h)

```{eval-rst}
.. doxygenstruct:: res_err_t
  :members:
```

## [Find Message by Index](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/v1/find_message.h)

```{eval-rst}
.. doxygenfunction:: find_message_by_index
```

### Response

```{eval-rst}
.. doxygenstruct:: res_find_msg_t
  :members:
```

### Message IDs from find message API call

```{eval-rst}
.. doxygenstruct:: find_msg_t
  :members:
```

## [Get Balance](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/v1/get_balance.h)

```{eval-rst}
.. doxygenfunction:: get_balance
```

### Response

```{eval-rst}
.. doxygenstruct:: res_balance_t
  :members:
```

### Balance object

```{eval-rst}
.. doxygenstruct:: get_balance_t
  :members:
```

## [Get Health](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/v1/get_health.h)

```{eval-rst}
.. doxygenfunction:: get_health
```

## [Get Message by ID](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/v1/get_message.h)

```{eval-rst}
.. doxygenfunction:: get_message_by_id
```

### Response

```{eval-rst}
.. doxygenstruct:: res_message_t
  :members:
```

### The Message Object

```{eval-rst}
.. doxygenstruct:: message_t
  :members:
```

## [Get Node Info](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/v1/get_node_info.h)

```{eval-rst}
.. doxygenfunction:: get_node_info
```

### Response

```{eval-rst}
.. doxygenstruct:: res_node_info_t
  :members:
```

### Node Info Object

```{eval-rst}
.. doxygenstruct:: get_node_info_t
  :members:
```

## [Get Output](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/v1/get_output.h)

```{eval-rst}
.. doxygenfunction:: get_output
```

### Response

```{eval-rst}
.. doxygenstruct:: res_output_t
  :members:
```

### Output object

```{eval-rst}
.. doxygenstruct:: get_output_t
  :members:
```

## [Get Outputs From Address](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/v1/get_outputs_from_address.h)

```{eval-rst}
.. doxygenfunction:: get_outputs_from_address
```

### Response

```{eval-rst}
.. doxygenstruct:: res_outputs_address_t
  :members:
```

### Address Outputs Object

```{eval-rst}
.. doxygenstruct:: get_outputs_address_t
  :members:
```

## [Get Tips](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/v1/get_tips.h)

```{eval-rst}
.. doxygenfunction:: get_tips
```

### Response

```{eval-rst}
.. doxygenstruct:: res_tips_t
  :members:
```

## [Send Message](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/v1/send_message.h)

```{eval-rst}
.. doxygenfunction:: send_indexation_msg
```

```{eval-rst}
.. doxygenfunction:: send_core_message
```

### Response

```{eval-rst}
.. doxygenstruct:: res_send_message_t
  :members:
```

## [Get Message Metadata](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/v1/get_message_metadata.h)

```{eval-rst}
.. doxygenfunction:: get_message_metadata
```

### Response

```{eval-rst}
.. doxygenstruct:: res_msg_meta_t
  :members:
```

```{eval-rst}
.. doxygenstruct:: msg_meta_t
  :members:
```

## [Get Message Children](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/v1/get_message_children.h)

```{eval-rst}
.. doxygenfunction:: get_message_children
```

### Response

```{eval-rst}
.. doxygenstruct:: res_msg_children_t
  :members:
```

```{eval-rst}
.. doxygenstruct:: msg_children_t
  :members:
```
