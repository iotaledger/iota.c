# Event API Reference

The Event API is event subscribers based on [TIP-28 Node Event API](https://github.com/iotaledger/tips/pull/66), it provides an easy way to subscribe node events via MQTT protocol.

## Event Client Configuration

```{eval-rst}
.. doxygenstruct:: event_client_config_t
  :members:
```

## Event IDs

```{eval-rst}
.. doxygenenum:: event_client_event_id_t
```

## Initialize Event Service

```{eval-rst}
.. doxygenfunction:: event_init
```

## Register Event Callback Handler

```{eval-rst}
.. doxygenfunction:: event_register_cb
```

## Subscribe To A Topic

```{eval-rst}
.. doxygenfunction:: event_subscribe
```

## Unsubscribe To A Topic

```{eval-rst}
.. doxygenfunction:: event_unsubscribe
```

## Start Event Service

```{eval-rst}
.. doxygenfunction:: event_start
```

## Stop Event Service

```{eval-rst}
.. doxygenfunction:: event_stop
```

## Destroy Event Service

```{eval-rst}
.. doxygenfunction:: event_destroy
```

## IOTA Event Topics

### milestone-info/latest

Use `TOPIC_MS_LATEST`

```
event_subscribe(event_client_handle_t client, int *mid, TOPIC_MS_LATEST, int qos);
```

### milestone-info/confirmed

```
event_subscribe(event->client, NULL, TOPIC_MS_CONGIRMED, 1);
```

### milestones

TODO

### messages

```
event_subscribe(event->client, NULL, TOPIC_MESSAGES, 1);
```

### messages/transaction

```
event_subscribe(event->client, NULL, TOPIC_MS_TRANSACTION, 1);
```

### messages/transaction/tagged-data

TODO

### messages/transaction/tagged-data/{tag}

TODO

### messages/tagged-data

```
event_subscribe(event->client, NULL, TOPIC_MS_TAGGED_DATA, 1);
```

### messages/tagged-data/{tag}

TODO

### transactions/{transaction ID}/included-message

TODO

### message-metadata/{message ID}

TODO

### message-metadata/referenced

TODO

### outputs/{Output ID}

```{eval-rst}
.. doxygenfunction:: event_sub_outputs_id
```

### outputs/nft/{NFT ID}

```{eval-rst}
.. doxygenfunction:: event_sub_outputs_nft_id
```

### outputs/aliases/{Alias ID}

```{eval-rst}
.. doxygenfunction:: event_sub_outputs_alias_id
```

### outputs/foundries/{Foundry ID}

```{eval-rst}
.. doxygenfunction:: event_sub_outputs_foundry_id
```

### outputs/unlock/{condition}/{address}

```{eval-rst}
.. doxygenfunction:: event_sub_outputs_unlock_address
```

### outputs/unlock/{condition}/{address}/spent

```{eval-rst}
.. doxygenfunction:: event_sub_outputs_unlock_address_spent
```

