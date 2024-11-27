# Account

Account which bundles all the functionality you need to build great crypto-powered user experiences. Requires:
* EIP-7702 & RIP-7212 deployed on the network utilizing it.
* [ORC-0001](https://www.ithaca.xyz/writings/orc-0001) integrated on the sequencer.
* [EIP-5792](https://eips.ethereum.org/EIPS/eip-5792) for dapps to utilize the smart contract's capabilities.

# Features out of the box

* Secure Login: Using WebAuthN-compatible credentials like PassKeys.
* Transact on any chain: Your account lives on the same address in every chain. Transactions get filled across chains by ERC7683-compatible fillers.
* ERC-1271 Signature Verification
* Upgradable: Ability for end-users to upgrade to a new version of the Account contract.
* Counterfactual Account abilities: Ability to batch execution into the initial 7702 auth transaction, and also sign before 7702 auth transaction (ERC-6492).
* Cheap transactions: Use BLS and L2 Optimized router contracts.
* Access Control:
* Multi-factor authentication:
* Call Batching:
* Identity based on real-world credentials: 
* Sponsored transactions: Either using ERC20 tokens, or subsidized by other applications.
* Account recovery: If you've lost your device, you can always recover using your friends or your email or identity mechanism.
