// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MultiSendCallOnly} from "./MultiSend.sol";
import "./utils/ECDSA.sol";
import "./utils/P256.sol";
import "./utils/WebAuthnP256.sol";

/// @title P256BatchDelegation
/// @author jxom <https://github.com/jxom>
/// @notice EIP-7702 Delegation contract that allows authorized P256 public keys to invoke calls on behalf of an Authority.
contract P256BatchDelegation is MultiSendCallOnly {
    /// @notice Thrown when the sender is not the Authority.
    error InvalidAuthority();

    /// @notice Thrown when a signature is invalid.
    error InvalidSignature();

    /// @notice List of authorized delegate public keys.
    ECDSA.PublicKey[] public delegates;

    /// @notice Internal `authorize` nonce used for replay protection.
    uint256 public authorizeNonce;

    /// @notice Internal `execute` nonce used for replay protection.
    uint256 public executeNonce;

    /// @notice Authorizes a new public key.
    /// @param publicKey - The public key to authorize.
    function authorize(ECDSA.PublicKey calldata publicKey) public {
        if (msg.sender != address(this)) revert InvalidAuthority();
        delegates.push(publicKey);
    }

    /// @notice Authorizes a new public key on behalf of the Authority, provided the Authority's signature.
    /// @param publicKey - The public key to authorize.
    /// @param signature - EOA secp256k1 signature over the public key.
    function authorize(ECDSA.PublicKey calldata publicKey, ECDSA.RecoveredSignature calldata signature) public {
        bytes32 digest = keccak256(abi.encodePacked(authorizeNonce++, publicKey.x, publicKey.y));
        address signer = ecrecover(digest, signature.v, bytes32(signature.r), bytes32(signature.s));
        if (signer != address(this)) revert InvalidSignature();
        delegates.push(publicKey);
    }

    /// @notice Revokes a delegate public key.
    /// @param delegateIndex - The index of the public key to revoke.
    function revoke(uint32 delegateIndex) public {
        if (msg.sender != address(this)) revert InvalidAuthority();
        delegates[delegateIndex] = delegates[delegates.length - 1];
        delegates.pop();
    }

    /// @notice Revokes a delegate public key on behalf of the Authority, provided the Authority's signature.
    /// @param delegateIndex - The index of the public key to revoke.
    /// @param signature - EOA secp256k1 signature over the delegate index.
    function revoke(uint32 delegateIndex, ECDSA.RecoveredSignature calldata signature) public {
        bytes32 digest = keccak256(abi.encodePacked(authorizeNonce++, delegateIndex));
        address signer = ecrecover(digest, signature.v, bytes32(signature.r), bytes32(signature.s));
        if (signer != address(this)) revert InvalidSignature();
        delegates[delegateIndex] = delegates[delegates.length - 1];
        delegates.pop();
    }

    /// @notice Executes a set of calls.
    /// @param calls - The calls to execute.
    function execute(bytes memory calls) public {
        if (msg.sender != address(this)) revert InvalidAuthority();
        multiSend(calls);
    }

    /// @notice Executes a set of calls on behalf of the Authority, provided a P256 signature over the calls and a delegate index.
    /// @param calls - The calls to execute.
    /// @param signature - The P256 signature over the calls: `p256.sign(keccak256(nonce ‖ calls))`.
    /// @param delegateIndex - The index of the delegate public key to use.
    /// @param prehash - Whether to SHA-256 hash the digest.
    function executeWithDelegate(
        bytes memory calls,
        ECDSA.Signature memory signature,
        uint32 delegateIndex,
        bool prehash
    ) public {
        bytes32 digest = keccak256(abi.encodePacked(executeNonce++, calls));
        if (prehash) digest = sha256(abi.encodePacked(digest));
        if (!P256.verify(digest, signature, delegates[delegateIndex])) {
            revert InvalidSignature();
        }
        multiSend(calls);
    }

    /// @notice Executes a set of calls on behalf of the Authority, provided a WebAuthn-wrapped P256 signature over the calls, the WebAuthn metadata, and an invoker index.
    /// @param calls - The calls to execute.
    /// @param signature - The WebAuthn-wrapped P256 signature over the calls: `p256.sign(keccak256(nonce ‖ calls))`.
    /// @param metadata - The WebAuthn metadata.
    /// @param delegateIndex - The index of the delegate public key to use.
    /// @param prehash - Whether to SHA-256 hash the digest.
    function executeWithDelegate(
        bytes memory calls,
        ECDSA.Signature memory signature,
        WebAuthnP256.Metadata memory metadata,
        uint32 delegateIndex,
        bool prehash
    ) public {
        bytes32 challenge = keccak256(abi.encodePacked(executeNonce++, calls));
        if (prehash) challenge = sha256(abi.encodePacked(challenge));
        if (!WebAuthnP256.verify(challenge, metadata, signature, delegates[delegateIndex])) revert InvalidSignature();
        multiSend(calls);
    }
}
