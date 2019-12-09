# IOTA Client Library  

IOTA client library implementation in C.  

## Build and test via Bazel  

```
bazel build //...
bazel test //...
```

## Build and test via CMake

```
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=$PWD -DCCLIENT_TEST=ON ..
make -j8 && make test
```

## Using iota.c in your Bazel project  

First, adding dependence libraries to your **WORKSPACE**:  

```
# The WORKSPACE file

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

git_repository(
    name = "org_iota_common",
    commit = "29269df072c793eeb545cc918c19535e9e52a1ee",
    remote = "git@github.com:iotaledger/iota_common.git",
)

git_repository(
    name = "org_iota_client",
    commit = "3d17e4370a7a162a1a886837d0f29dad40b62c86",
    remote = "git@github.com:iotaledger/iota.c.git",
)

git_repository(
    name = "rules_iota",
    commit = "e08b0038f376d6c82b80f5283bb0a86648bb58dc",
    remote = "https://github.com/iotaledger/rules_iota.git",
)

load("@rules_iota//:defs.bzl", "iota_deps")
iota_deps()
```

Second, adding it to dependencies in the **BUILD** file:  

```
# The BUILD file

package(default_visibility = ["//visibility:public"])

cc_binary(
    name = "my_app",
    srcs = ["my_app.c", ],
    deps = ["@org_iota_client//cclient/api",],
    visibility = ["//visibility:public"],
)

```

For more details, please visit [Bazel Concepts and Terminology](https://docs.bazel.build/versions/master/build-ref.html).  
## API List  

The client API consists of two API sets:  
* **Core APIs** are basic APIs in [API reference](https://docs.iota.org/docs/node-software/0.1/iri/references/api-reference).  
* **Extended APIs** are commonly used API functions for applications.

**Core APIs**  

* iota_client_add_neighbors()
* iota_client_attach_to_tangle()
* iota_client_broadcast_transactions()
* iota_client_check_consistency()
* iota_client_find_transactions()
* iota_client_get_balances()
* iota_client_get_inclusion_states()
* iota_client_get_neighbors()
* iota_client_get_node_api_conf()
* iota_client_get_node_info()
* iota_client_get_tips()
* iota_client_get_transactions_to_approve()
* iota_client_get_trytes()
* iota_client_remove_neighbors()
* iota_client_store_transactions()
* iota_client_were_addresses_spent_from()

**Extended APIs**  

* iota_client_broadcast_bundle()
* iota_client_find_transaction_objects()
* iota_client_get_account_data()
* iota_client_get_bundle()
* iota_client_get_inputs()
* iota_client_get_latest_inclusion()
* iota_client_get_new_address()
* iota_client_get_transaction_objects()
* iota_client_is_promotable()
* iota_client_prepare_transfers()
* iota_client_promote_transaction()
* iota_client_replay_bundle()
* iota_client_send_transfer()
* iota_client_send_trytes()
* iota_client_store_and_broadcast()
* iota_client_traverse_bundle()

## API Documentation  

TODO
