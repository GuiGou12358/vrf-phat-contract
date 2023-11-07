# VrfOracle

The Phat Contract `VrfOracle`, deployed on Phala Network (or testnet):
1) Listens the requests from the Smart Contract, deployed on Astar Network (or testnet)
2) Generates a random value between min and max values
3) Sends the value to the Smart Contract, deployed on Astar Network (or testnet)


## Build

To build the contract:

```bash
cargo contract build
```

## Run Integration tests

Unfortunately, the cross contract call doesn't work in a local environment. 
It means the JS contract used to compute the random value can not been reached and the tests can not be run for the time being.  
