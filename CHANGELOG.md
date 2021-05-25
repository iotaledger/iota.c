# v0.1.0-beta - 2021-05-25

This is the first C client library release for the [Chrysalis](https://chrysalis.docs.iota.org/introduction/what_is_chrysalis.html) network aka IOTA 1.5.  
The IOTA C Client documentation can be found in [here](https://iota-c-client.readthedocs.io/en/latest/index.html)  

Supported [REST Node APIs](https://github.com/iotaledger/protocol-rfcs/pull/27):  
* GET health
* GET /api/v1/info
* GET /api/v1/tips
* POST /api/v1/messages
* GET /api/v1/messages/{messageId}
* GET /api/v1/messages/{messageId}/metadata
* GET /api/v1/messages/{messageId}/children
* GET /api/v1/outputs/{outputId}
* GET /api/v1/addresses/ed25519/{address}
* GET /api/v1/addresses/ed25519/{address}/outputs
