<h1 align="center">
  <br>
  <a href="https://docs.iota.org/docs/client-libraries/0.1/getting-started/c-quickstart"><img src="iota-c.png"></a>
</h1>

<h2 align="center">The official C client library for interacting with the Tangle</h2>

<p align="center">
    <a href="https://docs.iota.org/docs/client-libraries/0.1/getting-started/c-quickstart" style="text-decoration:none;">
    <img src="https://img.shields.io/badge/Documentation%20portal-blue.svg?style=for-the-badge"
         alt="Developer documentation portal">
      </p>
<p align="center">
  <a href="https://discord.iota.org/" style="text-decoration:none;"><img src="https://img.shields.io/badge/Discord-9cf.svg?logo=discord" alt="Discord"></a>
    <a href="https://iota.stackexchange.com/" style="text-decoration:none;"><img src="https://img.shields.io/badge/StackExchange-9cf.svg?logo=stackexchange" alt="StackExchange"></a>
    <a href="https://github.com/iotaledger/iota.c/blob/master/LICENSE" style="text-decoration:none;"><img src="https://img.shields.io/github/license/iotaledger/iota.c.svg" alt="Apache 2.0 license"></a>
    <a href="https://docs.iota.org/docs/node-software/0.1/iri/references/api-reference" style="text-decoration:none;"><img src="https://img.shields.io/badge/Node%20API%20coverage-16/18%20commands-green.svg" alt="Supported IRI API endpoints"></a>
</p>
      
<p align="center">
  <a href="#about">About</a> ◈
  <a href="#prerequisites">Prerequisites</a> ◈
  <a href="#installation">Installation</a> ◈
  <a href="#getting-started">Getting started</a> ◈
  <a href="#api-reference">API reference</a> ◈
  <a href="#examples">Examples</a> ◈
  <a href="#supporting-the-project">Supporting the project</a> ◈
  <a href="#joining-the-discussion">Joining the discussion</a> 
</p>

---

## About

This is the **official** C client library, which allows you to do the following:
* Create transactions
* Read transactions
* Sign transactions
* Generate addresses

This is beta software, so there may be performance and stability issues.
Please report any issues in our [issue tracker](https://github.com/iotaledger/iota.c/issues/new/choose).

## Prerequisites

To use the IOTA C client library, you must have either [CMake](https://cmake.org/install/) or [Bazel](https://docs.bazel.build/versions/master/install.html) installed on your device.

## Installation

To install the IOTA C client library and its dependencies, you can use either CMake or Bazel

### CMake

1. Clone this repository

    ```bash
    git clone https://github.com/iotaledger/iota.c.git
    cd iota.c
    ```
    
2. Create a `build` directory in which to save the compiled library

    ```bash
    mkdir build && cd build
    ```
    
3. Set the path in which to save the `lib` directory
    
    ```bash
    cmake -DCMAKE_INSTALL_PREFIX=$PWD ..
    ```
    
4. Compile the code

    ```bash
    make -j8
    ```
    
Now, you're ready to start coding!

### Bazel

1. In the root of your Bazel project directory, create a file called `WORKSPACE` and add the following content:

    Replace the `$CCLIENT_COMMIT_HASH` placeholder with the latest Git commit hash of the `iota.c` repository.
    
    Replace the `$COMMON_COMMIT_HASH` placeholder with the latest Git commit hash of the `iota_common` repository.

    Replace the `$RULES_IOTA_COMMIT_HASH` placeholder with the latest Git commit hash of the `rules_iota` repository. 

    ```bash
    git_repository(
    name = "org_iota_common",
    commit = "$COMMON_COMMIT_HASH",
     remote = "https://github.com/iotaledger/iota_common.git",
    )
    
    git_repository(
        name = "org_iota_client",
        commit = "$CCLIENT_COMMIT_HASH",
        remote = "https://github.com/iotaledger/iota.c.git",
    )

    # external library build rules
    git_repository(
        name = "rules_iota",
        commit = "$RULES_IOTA_COMMIT_HASH",
        remote = "https://github.com/iotaledger/rules_iota.git",
    )

    load("@rules_iota//:defs.bzl", "iota_deps")

    iota_deps()
    ```

    This file tells Bazel to build the C library and its dependencies from GitHub.

2. Create a `BUILD` file and add the following to it:

    ```bash
    package(default_visibility = ["//visibility:public"])

    cc_binary(
        name = "cclient_app",
        copts = ["-DLOGGER_ENABLE"],
        srcs = ["cclient_app.c", "cclient_app.h",],
        deps = ["@org_iota_client//cclient:api",],
        visibility = ["//visibility:public"],
    )
    ```

    This file tells Bazel to build you project's source files (`cclient_app.c` and `cclient_app.h`), using the `api` package as a dependency.
    
Now, you're ready to start coding!

## Getting Started

After [installing the library](#installation), you can connect to an IRI node to send transactions to it and interact with the ledger.
An extended guide can be found on our [documentation portal](https://docs.iota.org/docs/client-libraries/0.1/getting-started/c-quickstart), we strongly recommend you to go here. A quickstart tutorial is shown below.

To connect to a local IRI node, you can do the following:

```cpp
#include "cclient/api/core/core_api.h"
#include "cclient/api/extended/extended_api.h"

#include <inttypes.h>
#include "iota_client_service/config.h"
#include "iota_client_service/client_service.h"

retcode_t get_iota_node_info(iota_client_service_t *iota_client_service, get_node_info_res_t *node_response) {
    retcode_t ret = RC_ERROR;
    // Connect to the node
    ret = iota_client_get_node_info(iota_client_service, node_response);

    // If the node returned data, print it to the console
    if (ret == RC_OK) {
        printf("appName %s \n", node_response->app_name->data);
        printf("appVersion %s \n", node_response->app_version->data);

        printf("latestMilestone ");
        flex_trit_print(node_response->latest_milestone, NUM_TRITS_HASH);
        printf("\n");
        printf("latestMilestoneIndex %u\n", (uint32_t) node_response->latest_milestone_index);
        printf("latestSolidSubtangleMilestoneIndex %u\n", (uint32_t)
        node_response->latest_solid_subtangle_milestone_index);

        printf("milestoneStartIndex %u\n", node_response->milestone_start_index);
        printf("neighbors %d \n", node_response->neighbors);
        printf("packetsQueueSize %d \n", node_response->packets_queue_size);
        printf("tips %u \n", node_response->tips);
        printf("transactionsToRequest %u\n", node_response->transactions_to_request);
        size_t num_features = get_node_info_req_features_num(node_response);
        for (; num_features > 0; num_features--) {
            printf("%s, ", get_node_info_res_features_at(node_response, num_features - 1));
            printf("\n");
        }

    } else {
        printf("Failed to connect to the node.");
    }

    done:

    // Free the response object
    get_node_info_res_free(&node_response);
    return ret;
}

int main(void) {
    // Create the client service
    iota_client_service_t iota_client_service;
    init_iota_client(&iota_client_service);
    // Allocate a response object
    get_node_info_res_t *node_response = get_node_info_res_new();
    // Call the getNodeInfo endpoint
    get_iota_node_info(&iota_client_service, node_response);
}
```

## API reference

Here are some of the most commonly used API functions:

The IOTA C client library consists of two sets of API:  
* **Core API:** Allows you to call the [IRI node API endpoints](https://docs.iota.org/docs/iri/0.1/references/api-reference).  
* **Extended API:** Extends the core API with functions that allow you to create transactions, generate addresses, sign transactions, and more.

### Core API 

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
* iota_client_get_transactions_to_approve()
* iota_client_get_trytes()
* iota_client_remove_neighbors()
* iota_client_store_transactions()
* iota_client_were_addresses_spent_from()

### Extended API 

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

## Examples

You can find example templates in this [GitHub repository](https://github.com/oopsmonk/iota_c_templates) to help you integrate IOTA into your own applications.

## Supporting the project

If the IOTA C client library has been useful to you and you feel like contributing, consider posting a [bug report](https://github.com/iotaledger/iota.c/issues/new-issue), feature request or a [pull request](https://github.com/iotaledger/iota.c/pulls/).  
We have some [basic contribution guidelines](CONTRIBUTING.md) to keep our code base stable and consistent.

### Running test cases

To run tests, do the following:

### CMake

```bash
cmake -DCMAKE_INSTALL_PREFIX=$PWD -DCCLIENT_TEST=ON ..
make test
```

#### Bazel

```bash
bazel test //cclient/...
```

## Joining the discussion

If you want to get involved in the community, need help with getting set up, have any issues related with the library or just want to discuss blockchain, distributed ledgers, and IoT with other people, feel free to join our [Discord](https://discord.iota.org/).
