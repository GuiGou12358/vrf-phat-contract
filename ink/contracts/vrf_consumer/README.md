# VRF Consumer

The Smart Contract `VrfConsumer`, deployed on Astar Network (or testnet):
1) Registers a request to get a random value between min and max values
2) Sends the request into the message queue that will be consumed by the Phat Contract `VrfOracle` deployed on Phala Network (or testnet)
3) Listens the reply to the Phat Contract `VrfOracle` with the generated random value. The Ink! Smart Contract checks if the attestor (ie the phat contract) is granted and if the hash of the source code used to compute the random value is correct.
4) Saves the random value to be displayed in the UI.

It uses the crate `phat_rollup_anchor_ink` and supports the following operations:
 - configure the attestor(s) authorized to send the random value. Only an address granted as `MANAGER` can do it.
 - send a request to get a random value between min and max values. All users can do it.
 - handle the messages to provide the random value. Only an address granted as `ATTESTOR` can do it.
 - display the last random value received by requestor.
 - allow meta transactions to separate the attestor and the payer.
 - manage the roles and grant an address as `ADMIN`, `MANAGER`, `ATTESTOR`. Only the admin can do it.

By default, the contract owner is granted as `ADMIN` and `MANAGER` but it is not granted as `ATTESTOR`.

## Build

To build the contract:

```bash
cargo contract build
```

## Run e2e tests

Before you can run the test, you have to install a Substrate node with pallet-contracts. By default, `e2e tests` require that you install `substrate-contracts-node`. You do not need to run it in the background since the node is started for each test independently. To install the latest version:
```bash
cargo install contracts-node --git https://github.com/paritytech/substrate-contracts-node.git
```

If you want to run any other node with pallet-contracts you need to change `CONTRACTS_NODE` environment variable:
```bash
export CONTRACTS_NODE="YOUR_CONTRACTS_NODE_PATH"
```

And finally execute the following command to start e2e tests execution.
```bash
cargo test --features e2e-tests
```
