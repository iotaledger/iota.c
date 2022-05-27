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

Use `TOPIC_MILESTONE_LATEST`

```
event_subscribe(event_client_handle_t client, int *mid, TOPIC_MS_LATEST, int qos);
```

### milestone-info/confirmed

```
event_subscribe(event->client, NULL, TOPIC_MILESTONE_CONGIRMED, 1);
```

### milestones

TODO

### blocks

```
event_subscribe(event->client, NULL, TOPIC_BLOCKS, 1);
```

### blocks/transaction

```
event_subscribe(event->client, NULL, TOPIC_BLK_TRANSACTION, 1);
```

### blocks/transaction/tagged-data

TODO

### blocks/transaction/tagged-data/{tag}

TODO

### blocks/tagged-data

```
event_subscribe(event->client, NULL, TOPIC_BLK_TAGGED_DATA, 1);
```

### blocks/tagged-data/{tag}

TODO

### transactions/{transaction ID}/included-block

TODO

### block-metadata/{block ID}

TODO

### block-metadata/referenced

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

