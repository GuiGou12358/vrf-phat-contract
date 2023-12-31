# VRF with Ink! Smart Contract (on Astar Network) and Ink! Phat Contract (on Phala Network)

Scenario described here in the communication betwen Ink! Smart Contract on Astar Network and Ink! Phat Contract on Phala Network:
1) A request to compute a random value between min and max values is stored in the Smart Contract `VrfConsumer` (on Astar Network)
2) The Phat Contract `VrfOracle` (on Phala Network) pulls the request from the Smart Contract `VrfConsumer` (on Astar Network), generates the random value and sends the number to the Smart Contract `VrfConsumer` (on Astar Network)
3) The Smart Contract `VrfConsumer` (on Astar Network) verifies the data used by the Phat Contract `VrfOracle` and saves the number to be displayed in the UI 

You can find a demo here: https://vrf-decentralized-oracle.substrate.fi/

The Phat Contract and Ink! Smart Contract have been built with the Phat Offchain Rollup.
The full documentation of this SDK can be found here: https://github.com/Phala-Network/phat-offchain-rollup


## Phat Contract `VrfOracle`

To deploy this Phat Contract you can build the contract or use existing artifacts

More information here: [phat/contracts/vrf_oracle/README.md](phat/contracts/vrf_oracle/README.md)

### Build the contract

To build the contract:
```bash
cd phat/contracts/vrf_oracle
cargo contract build
```

### Use existing artifacts
All artifacts are here: [phat/artifacts](phat/artifacts)


## Ink! Smart Contract `VrfConsumer`

To deploy this Ink! Smart Contract you can build the contract or use existing artifacts

More information here: [ink/contracts/vrf_consumer/README.md](ink/contracts/vrf_consumer/README.md)

### Build the contract

To build the contract:
```bash
cd ink/contracts/vrf_consumer
cargo contract build
```

### Use existing artifacts
All artifacts are here: [ink/artifacts](ink/artifacts)



## Configure Phat Contract `VrfOracle`
You have to configure the rpc, the pallet id, the call id and the contract id to call the Smart Contract `VrfConsumer`.

For example:
```
RPC=https://shibuya.public.blastapi.io
PALLET_ID=70
CALL_ID=6
#public key of the contract WJFx4kaW59yMD4rpQQbWnUErKr35fo4aEEM7HuukkJkbq7a
CONTRACT_ID=0x0ffc44222f454540273d41249c51fec33567258bf4b4f2d67804fda7ddd504dc
```
![config_target_contract](https://github.com/GuiGou12358/decentralized_oracle-vrf/assets/92046056/aee3b404-91b6-46a9-8882-1e38a94c65d3)


#### Enable Meta-Tx

Meta transaction allows the Phat Contract to submit rollup tx with attest key signature while using arbitrary account to pay the gas fee. 
To enable meta tx in the unit test you have to set the private key

For example, the private key of account //bob: 0x398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89

If you don't use Meta-Tx, you have to be sure that address of Phat Contract `VrfOracle` will be able to pay transaction fees on Astar Network.

## Configure Ink! Smart Contract `VrfConsumer`

### Grant the attestor
You have to grant the Phat Contract `VrfOracle` as attestor in the Smart Contract `VrfConsumer`.

If you use the Meta-Tx, you have to grant the ecdsa address.

![image](https://github.com/decentralized-oracles/vrf/assets/92046056/896564c3-26d6-484e-8746-1ffbf3b71bf3)

If you don't use the Meta-Tx, you have to grant the sr25519 public key.

![image](https://github.com/decentralized-oracles/vrf/assets/92046056/bbcc1a56-28ad-4d8c-b5b0-bc87f0ef5e08)

And grant the Phat Contract as attestor 

![configure attestor](https://github.com/GuiGou12358/decentralized_oracle-vrf/assets/92046056/3f91f50b-0007-4a6d-9b37-badb04946620)


## Test

### Ink! Smart Contract `VrfConsumer` - Request a random between min and max values

![image](https://github.com/decentralized-oracles/vrf/assets/92046056/b1dd85d4-5fde-4f46-b642-29f307cd8bff)

### Phat Contract `VrfOracle` - Pull the request, generate the random value and send the number to the Smart Contract `VrfConsumer`

![image](https://github.com/decentralized-oracles/vrf/assets/92046056/fbbcaea7-c5c7-4bd8-8eec-03bbaa53b352)

### Ink! Smart Contract `VrfConsumer` - Read the random number generated by the VRF

![image](https://github.com/decentralized-oracles/vrf/assets/92046056/5dc60bd8-1907-48c7-839b-1f42398fefb2)

