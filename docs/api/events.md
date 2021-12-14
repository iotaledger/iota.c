# Event API Reference

The Event API is event subscribers based on [RFC: Node Event API](https://github.com/iotaledger/protocol-rfcs/pull/33), it provides an easy way to subscribe node events via MQTT protocol.

## [Event Client Configuration](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/node_event.h)

```{eval-rst}
.. doxygenstruct:: event_client_config_t
  :members:
```

## [Event IDs](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/node_event.h)

```{eval-rst}
.. doxygenenum:: event_client_event_id_t
```

## [Initialize Event Service](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/node_event.h)

```{eval-rst}
.. doxygenfunction:: event_init
```

## [Register Event Callback Handler](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/node_event.h)

```{eval-rst}
.. doxygenfunction:: event_register_cb
```

## [Subscribe To A Topic](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/node_event.h)

```{eval-rst}
.. doxygenfunction:: event_subscribe
```

## [Unsubscribe To A Topic](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/node_event.h)

```{eval-rst}
.. doxygenfunction:: event_unsubscribe
```

## [Start Event Service](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/node_event.h)

```{eval-rst}
.. doxygenfunction:: event_start
```

## [Stop Event Service](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/node_event.h)

```{eval-rst}
.. doxygenfunction:: event_stop
```

## [Destroy Event Service](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/node_event.h)

```{eval-rst}
.. doxygenfunction:: event_destroy
```

## IOTA Node Events

### [Confirmed Milestones](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/sub_milestones_confirmed.h)

```{eval-rst}
.. doxygenstruct:: milestone_confirmed_t
  :members:
```

#### Parse Confirmed Milestone JSON response
```{eval-rst}
.. doxygenfunction:: parse_milestones_confirmed
```

### [The Latest Milestone](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/sub_milestone_latest.h)

```{eval-rst}
.. doxygenstruct:: milestone_latest_t
  :members:
```

#### Parse Confirmed Milestone JSON response
```{eval-rst}
.. doxygenfunction:: parse_milestone_latest
```

### [The Message Metadata](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/sub_messages_metadata.h)

```{eval-rst}
.. doxygenstruct:: msg_metadata_t
  :members:
```

#### Subscribe for messages/{messageid}/metadata event
```{eval-rst}
.. doxygenfunction:: event_subscribe_msg_metadata
```

#### Allocate a message metadata onject
```{eval-rst}
.. doxygenfunction:: res_msg_metadata_new
```

#### Free a message metadata object
```{eval-rst}
.. doxygenfunction:: res_msg_metadata_free
```

#### Parse a message metadata response
```{eval-rst}
.. doxygenfunction:: parse_messages_metadata
```

#### Get the count of parent message ids
```{eval-rst}
.. doxygenfunction:: res_msg_metadata_parents_count
```

#### Get a parent message ID by index
```{eval-rst}
.. doxygenfunction:: res_msg_metadata_parent_get
```

### [The Output Payloads](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/sub_outputs_payload.h)

```{eval-rst}
.. doxygenstruct:: event_outputs_payload_t
  :members:
```

```{eval-rst}
.. doxygenstruct:: event_output_t
  :members:
```

#### Subscribe for addresses/{address}/outputs event
```{eval-rst}
.. doxygenfunction:: event_sub_address_outputs
```

#### Subscribe for outputs/{outputId} event
```{eval-rst}
.. doxygenfunction:: event_sub_outputs_id
```

#### Parse the outputs payload
```{eval-rst}
.. doxygenfunction:: event_parse_outputs_payload
```

### [The Serialized Outputs](https://github.com/iotaledger/iota.c/blob/dev/src/client/api/events/sub_serialized_output.h)

#### Subscribe for transactions/{transactionId}/included_message event
```{eval-rst}
.. doxygenfunction:: event_sub_txn_included_msg
```

#### Subscribe for messages/indexation/{index} event
```{eval-rst}
.. doxygenfunction:: event_sub_msg_indexation
```