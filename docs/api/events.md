# Event API Reference

The Event API is event subscribers based on [RFC: Node Event API](https://github.com/iotaledger/protocol-rfcs/pull/33), it provides an easy way to subscribe node events via MQTT protocol.

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

## IOTA Node Events

### Confirmed Milestones

```{eval-rst}
.. doxygenstruct:: milestone_confirmed_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: parse_milestones_confirmed
```

### The Latest Milestone

```{eval-rst}
.. doxygenstruct:: milestone_latest_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: parse_milestone_latest
```
