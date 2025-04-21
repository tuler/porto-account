// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AccountRegistry} from "./AccountRegistry.sol";
import {LibBitmap} from "solady/utils/LibBitmap.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {LibEIP7702} from "solady/accounts/LibEIP7702.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";
import {ReentrancyGuardTransient} from "solady/utils/ReentrancyGuardTransient.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {LibBit} from "solady/utils/LibBit.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";
import {LibStorage} from "solady/utils/LibStorage.sol";
import {CallContextChecker} from "solady/utils/CallContextChecker.sol";
import {FixedPointMathLib as Math} from "solady/utils/FixedPointMathLib.sol";
import {TokenTransferLib} from "./libraries/TokenTransferLib.sol";
import {LibNonce} from "./libraries/LibNonce.sol";
import {LibPREP} from "./libraries/LibPREP.sol";
import {IDelegation} from "./interfaces/IDelegation.sol";
import {IEntryPoint} from "./interfaces/IEntryPoint.sol";

/// @title EntryPoint
/// @notice Enables atomic verification, gas compensation and execution across eoas.
/// @dev
/// The EntryPoint allows relayers to submit payloads on one or more eoas,
/// and get compensated for the gas spent in an atomic transaction.
/// It serves the following purposes:
/// - Facilitate fair gas compensation to the relayer.
///   This means capping the amount of gas consumed,
///   such that it will not exceed the signed gas stipend,
///   and ensuring the relayer gets compensated even if the call to the eoa reverts.
///   This also means minimizing the risk of griefing the relayer, in areas where
///   we cannot absolutely guarantee compensation for gas spent.
/// - Ensures that the eoa can safely compensate the relayer.
///   This means ensuring that the eoa cannot be drained.
///   This means ensuring that the compensation is capped by the signed max amount.
///   Tokens can only be deducted from an eoa once per signed nonce.
/// - Minimize chance of censorship.
///   This means once an UserOp is signed, it is infeasible to
///   alter or rearrange it to force it to fail.
contract EntryPoint is
    IEntryPoint,
    EIP712,
    Ownable,
    CallContextChecker,
    ReentrancyGuardTransient
{
    using LibERC7579 for bytes32[];
    using EfficientHashLib for bytes32[];
    using LibBitmap for LibBitmap.Bitmap;

    ////////////////////////////////////////////////////////////////////////
    // Errors
    ////////////////////////////////////////////////////////////////////////

    /// @dev Unable to perform the payment.
    error PaymentError();

    /// @dev Unable to verify the user op. The user op may be invalid.
    error VerificationError();

    /// @dev Unable to perform the call.
    error CallError();

    /// @dev Unable to perform the verification and the call.
    error VerifiedCallError();

    /// @dev Out of gas to perform the call operation.
    error InsufficientGas();

    /// @dev The order has already been filled.
    error OrderAlreadyFilled();

    /// @dev The simulate execute run has failed. Try passing in more gas to the simulation.
    error SimulateExecuteFailed();

    /// @dev A PreOp's EOA must be the same as its parent UserOp's.
    error InvalidPreOpEOA();

    /// @dev The PreOp cannot be verified to be correct.
    error PreOpVerificationError();

    /// @dev Error calling the sub UserOp's `executionData`.
    error PreOpCallError();

    /// @dev The EOA's delegation implementation is not supported.
    error UnsupportedDelegationImplementation();

    /// @dev The simulation has passed.
    error SimulationPassed(uint256 gUsed);

    ////////////////////////////////////////////////////////////////////////
    // Events
    ////////////////////////////////////////////////////////////////////////

    /// @dev The nonce sequence of `eoa` is invalidated up to (inclusive) of `nonce`.
    /// The new available nonce will be `nonce + 1`.
    event NonceInvalidated(address indexed eoa, uint256 nonce);

    /// @dev Emitted when a UserOp (including PreOps) is executed.
    /// This event is emitted in the `execute` function.
    /// - `incremented` denotes that `nonce`'s sequence has been incremented to invalidate `nonce`,
    /// - `err` denotes the resultant error selector.
    /// If `incremented` is true and `err` is non-zero, the UserOp was successful.
    /// For PreOps where the nonce is skipped, this event will NOT be emitted..
    event UserOpExecuted(address indexed eoa, uint256 indexed nonce, bool incremented, bytes4 err);

    ////////////////////////////////////////////////////////////////////////
    // Constants
    ////////////////////////////////////////////////////////////////////////

    /// @dev For EIP712 signature digest calculation for the `execute` function.
    bytes32 public constant USER_OP_TYPEHASH = keccak256(
        "UserOp(bool multichain,address eoa,Call[] calls,uint256 nonce,address payer,address paymentToken,uint256 prePaymentMaxAmount,uint256 totalPaymentMaxAmount,uint256 combinedGas,bytes[] encodedPreOps)Call(address to,uint256 value,bytes data)"
    );

    /// @dev For EIP712 signature digest calculation for PreOps in the `execute` functions.
    bytes32 public constant PRE_OP_TYPEHASH = keccak256(
        "PreOp(bool multichain,address eoa,Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)"
    );

    /// @dev For EIP712 signature digest calculation for the `execute` function.
    bytes32 public constant CALL_TYPEHASH = keccak256("Call(address to,uint256 value,bytes data)");

    /// @dev For EIP712 signature digest calculation.
    bytes32 public constant DOMAIN_TYPEHASH = _DOMAIN_TYPEHASH;

    /// @dev Nonce prefix to signal that the payload is to be signed with EIP712 without the chain ID.
    /// This constant is a pun for "chain ID 0".
    uint16 public constant MULTICHAIN_NONCE_PREFIX = 0xc1d0;

    /// @dev For ensuring that the remaining gas is sufficient for a self-call with
    /// overhead for cleaning up after the self-call. This also has an added benefit
    /// of preventing the censorship vector of calling `execute` in a very deep call-stack.
    /// With the 63/64 rule, and an initial gas of 30M, we can approximately make
    /// around 339 recursive calls before the amount of gas passed in drops below 100k.
    /// The EVM has a maximum call depth of 1024.
    uint256 internal constant _INNER_GAS_OVERHEAD = 100000;

    /// @dev The amount of expected gas for refunds.
    /// Should be enough for a cold zero to non-zero SSTORE + a warm SSTORE + a few SLOADs.
    uint256 internal constant _REFUND_GAS = 50000;

    ////////////////////////////////////////////////////////////////////////
    // Storage
    ////////////////////////////////////////////////////////////////////////

    /// @dev Holds the storage.
    struct EntryPointStorage {
        /// @dev Mapping of (`eoa`, `seqKey`) to nonce sequence.
        /// We use a `LibStorage.Ref` instead of a uint64 for performance.
        mapping(address => mapping(uint192 => LibStorage.Ref)) nonceSeqs;
        /// @dev Mapping of (`eoa`, `nonce`) to the error selector.
        /// If `uint64(nonce) < nonceSeqs[eoa][uint192(nonce >> 64)]`,
        /// it means that the nonce has either been used or invalidated,
        /// and a non-zero error selector denotes an error.
        /// Otherwise, if `uint64(nonce) >= nonceSeqs[eoa][uint192(nonce >> 64)]`,
        /// we would expect that the error selector is zero (i.e. uninitialized).
        mapping(address => mapping(uint256 => bytes4)) errs;
        /// @dev A bitmap to mark ERC7683 order IDs as filled, to prevent filling replays.
        LibBitmap.Bitmap filledOrderIds;
    }

    /// @dev Returns the storage pointer.
    function _getEntryPointStorage() internal pure returns (EntryPointStorage storage $) {
        // Truncate to 9 bytes to reduce bytecode size.
        uint256 s = uint72(bytes9(keccak256("PORTO_ENTRY_POINT_STORAGE")));
        assembly ("memory-safe") {
            $.slot := s
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // Constructor
    ////////////////////////////////////////////////////////////////////////

    constructor(address initialOwner) payable {
        _initializeOwner(initialOwner);
    }

    ////////////////////////////////////////////////////////////////////////
    // Main
    ////////////////////////////////////////////////////////////////////////

    /// @dev Executes a single encoded user operation.
    /// `encodedUserOp` is given by `abi.encode(userOp)`, where `userOp` is a struct of type `UserOp`.
    /// If sufficient gas is provided, returns an error selector that is non-zero
    /// if there is an error during the payment, verification, and call execution.
    function execute(bytes calldata encodedUserOp)
        public
        payable
        virtual
        nonReentrant
        returns (bytes4 err)
    {
        (, err) = _execute(encodedUserOp, 0, 0);
    }

    /// @dev Executes the array of encoded user operations.
    /// Each element in `encodedUserOps` is given by `abi.encode(userOp)`,
    /// where `userOp` is a struct of type `UserOp`.
    function execute(bytes[] calldata encodedUserOps)
        public
        payable
        virtual
        nonReentrant
        returns (bytes4[] memory errs)
    {
        // This allocation and loop was initially in assembly, but I've normified it for now.
        errs = new bytes4[](encodedUserOps.length);
        for (uint256 i; i < encodedUserOps.length; ++i) {
            // We reluctantly use regular Solidity to access `encodedUserOps[i]`.
            // This generates an unnecessary check for `i < encodedUserOps.length`, but helps
            // generate all the implicit calldata bound checks on `encodedUserOps[i]`.
            (, errs[i]) = _execute(encodedUserOps[i], 0, 0);
        }
    }

    /// @notice This is a helper simulate function that allows devs to fetch the gas needed for UserOps
    /// @dev There are 2 kinds of simulation runs
    /// 1. Primary - Simulates the userOp with infinite combined gas, and returns a gasUsed number.
    /// 2. Verification - Uses the gasUsed number from the primary gas run, to add to the paymentAmount value.
    /// Using the formula --> gasAmount = gasUsed * paymentPerGas.
    /// If the SimulationMode is set to PREPAY_VERIFY, then gasAmount is added to userOp.prePayment.
    /// If the SimulationMode is set to POSTPAY_VERIFY, then gasAmount is added to userOp.totalPayment. (effectively adding gas amount to postPayment)
    /// In addition to the gasAmounts, combined gas in a verification run is set as `userOp.combinedGas = gasUsed + combinedGasOffset`
    /// If the SimulationMode is set to SANS_VERIFY, then only the primary simulation run is made.
    /// @dev If the execution fails during either of the simulation runs, the whole function reverts.
    /// @dev In SANS_VERIFY, the returned combinedGas is always 0.
    function simulateExecute(
        SimulateMode mode,
        uint256 paymentPerGas,
        uint256 combinedGasFactor,
        bytes calldata encodedUserOp
    ) public payable virtual returns (uint256 gasUsed, uint256 combinedGas) {
        // Set the simulation flag to true
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 0x10da5c7e) // function selector of simulateSelfCall TODO: mine to 0xffffffff
            mstore(add(m, 0x20), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) // During the primary run, the combinedGasOverride is type(uint256).max
            mstore(add(m, 0x40), 0x40) // encodedUserOp
            mstore(add(m, 0x60), encodedUserOp.length)
            calldatacopy(add(m, 0x80), encodedUserOp.offset, encodedUserOp.length)

            let success :=
                call(gas(), address(), 0, add(m, 0x1c), add(encodedUserOp.length, 0x64), 0x00, 0x40)

            if success {
                // Simulate Self Call should *always* fail
                revert(0x00, 0x00)
            }

            let err := shl(224, shr(224, mload(0)))
            // Check if first 4 bytes are equal to SimulationPassed(uint256)
            if iszero(eq(err, 0x4f0c028c00000000000000000000000000000000000000000000000000000000)) {
                returndatacopy(m, 0x00, returndatasize())
                revert(m, returndatasize())
            }

            // Execute was successful
            gasUsed := mload(0x04)
        }

        UserOp memory u = abi.decode(encodedUserOp, (UserOp));
        // Check if verification step is needed
        if (mode == SimulateMode.SANS_VERIFY) {
            return (gasUsed, 0);
        } else {
            uint256 gasAmount = paymentPerGas * gasUsed;

            if (mode == SimulateMode.PREPAY_VERIFY) {
                u.prePaymentAmount += gasAmount;
                u.prePaymentMaxAmount += gasAmount;
            }

            u.totalPaymentAmount += gasAmount;
            u.totalPaymentMaxAmount += gasAmount;
        }

        u.combinedGas += gasUsed * combinedGasFactor / 10_000; // Combined gas factor is in basis points
        combinedGas = u.combinedGas;

        bytes memory updatedEncodedUserOp = abi.encode(u);

        // Set the simulation flag to true
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 0x10da5c7e) // function selector of simulateSelfCall
            mstore(add(m, 0x20), 0) // During the verification run, the combinedGasOverride is 0.
            mstore(add(m, 0x40), 0x40) // encodedUserOp
            mcopy(add(m, 0x60), updatedEncodedUserOp, mload(updatedEncodedUserOp))

            // Zeroize return slots
            mstore(0x00, 0)
            mstore(0x20, 0)

            let success :=
                call(gas(), address(), 0, add(m, 0x1c), add(encodedUserOp.length, 0x64), 0x00, 0x40)

            if success {
                // Simulate Self Call should *always* fail
                revert(0x00, 0x00)
            }

            let err := shl(224, shr(224, mload(0)))
            // Check if first 4 bytes are equal to SimulationPassed(uint256)
            if iszero(eq(err, 0x4f0c028c00000000000000000000000000000000000000000000000000000000)) {
                returndatacopy(m, 0x00, returndatasize())
                revert(m, returndatasize())
            }

            // Execute was successful
            gasUsed := mload(0x04)
        }
    }

    function simulateSelfCall(uint256 combinedGasOverride, bytes calldata encodedUserOp) public {
        // If Simulation Fails, then it will revert here.
        (uint256 gUsed, bytes4 err) = _execute(encodedUserOp, combinedGasOverride, 1);

        if (err != 0) {
            assembly ("memory-safe") {
                mstore(0x00, shl(224, err))
                revert(0x00, 0x20)
            }
        }

        // If Simulation Passes, then it will revert here.
        revert SimulationPassed(gUsed);
    }

    /// @dev Extracts the UserOp from the calldata bytes, with minimal checks.
    function _extractUserOp(bytes calldata encodedUserOp)
        internal
        virtual
        returns (UserOp calldata u)
    {
        // This function does NOT allocate memory to avoid quadratic memory expansion costs.
        // Otherwise, it will be unfair to the UserOps at the back of the batch.
        assembly ("memory-safe") {
            let t := calldataload(encodedUserOp.offset)
            u := add(t, encodedUserOp.offset)
            // Bounds check. We don't need to explicitly check the fields here.
            // In the self call functions, we will use regular Solidity to access the
            // dynamic fields like `signature`, which generate the implicit bounds checks.
            if or(shr(64, t), lt(encodedUserOp.length, 0x20)) { revert(0x00, 0x00) }
        }
    }
    /// @dev Extracts the PreOp from the calldata bytes, with minimal checks.

    function _extractPreOp(bytes calldata encodedPreOp)
        internal
        virtual
        returns (PreOp calldata p)
    {
        UserOp calldata u = _extractUserOp(encodedPreOp);
        assembly ("memory-safe") {
            p := u
        }
    }

    /// @dev Executes a single encoded UserOp.
    /// @dev If simulationFlags is non-zero, then all errors are bubbled up.
    /// Currently there can only be 2 modes - simulation mode, and execution mode.
    /// But we use a uint256 for efficient stack operations, and more flexiblity in the future.
    /// Note: We keep the simulationFlags in the stack/memory (TSTORE doesn't work) to make sure they are reset in each new call context,
    /// to provide protection against attacks which could spoof the execute function to believe it is in simulation mode.
    function _execute(
        bytes calldata encodedUserOp,
        uint256 combinedGasOverride,
        uint256 simulationFlags
    ) internal virtual returns (uint256 gUsed, bytes4 err) {
        UserOp calldata u = _extractUserOp(encodedUserOp);

        uint256 g = Math.coalesce(uint96(combinedGasOverride), u.combinedGas);
        uint256 gStart = gasleft();

        if (
            u.prePaymentMaxAmount > u.totalPaymentMaxAmount
                || u.prePaymentAmount > u.prePaymentMaxAmount
                || u.totalPaymentAmount > u.totalPaymentMaxAmount
        ) {
            err = PaymentError.selector;

            if (simulationFlags == 1) {
                revert PaymentError();
            }
        }

        // TODO: Fix later
        // unchecked {
        //     // Check if there's sufficient gas left for the gas-limited self calls
        //     // via the 63/64 rule. This is for gas estimation. If the total amount of gas
        //     // for the whole transaction is insufficient, revert.
        //     if (((gasleft() * 63) >> 6) < Math.saturatingAdd(g, _INNER_GAS_OVERHEAD)) {
        //         if (!_isSimulationV2()) revert InsufficientGas();
        //     }
        // }

        // if (u.supportedDelegationImplementation != address(0)) {
        //     if (delegationImplementationOf(u.eoa) != u.supportedDelegationImplementation) {
        //         if (!_isSimulationV2()) err = UnsupportedDelegationImplementation.selector;
        //     }
        // }

        if (u.supportedDelegationImplementation != address(0)) {
            if (delegationImplementationOf(u.eoa) != u.supportedDelegationImplementation) {
                if (!isSimulation) err = UnsupportedDelegationImplementation.selector;
            }
        }

        address payer = Math.coalesce(u.payer, u.eoa);

        // Early skip the entire pay-verify-call workflow if the payer lacks tokens,
        // so that less gas is wasted when the UserOp fails.
        if (u.prePaymentAmount != 0 && err == 0) {
            if (TokenTransferLib.balanceOf(u.paymentToken, payer) < u.prePaymentAmount) {
                err = PaymentError.selector;

                if (simulationFlags == 1) {
                    revert PaymentError();
                }
            }
        }

        bool selfCallSuccess;
        // We'll use assembly for frequently used call related stuff to save massive memory gas.
        assembly ("memory-safe") {
            let m := mload(0x40) // Grab the free memory pointer.
            if iszero(err) {
                // Copy the encoded user op to the memory to be ready to pass to the self call.
                calldatacopy(add(m, 0x40), encodedUserOp.offset, encodedUserOp.length)
                mstore(m, 0x00000000) // `selfCallPayVerifyCall537021665()`.
                // The word after the function selector contains the simulation flags.
                mstore(add(m, 0x20), simulationFlags)
                mstore(0x00, 0) // Zeroize the return slot.

                // To prevent griefing, we need to do a non-reverting gas-limited self call.
                // If the self call is successful, we know that the payment has been made,
                // and the sequence for `nonce` has been incremented.
                // For more information, see `selfCallPayVerifyCall537021665()`.
                selfCallSuccess :=
                    call(g, address(), 0, add(m, 0x1c), add(encodedUserOp.length, 0x44), 0x00, 0x20)
                err := mload(0x00) // The self call will do another self call to execute.

                if iszero(selfCallSuccess) {
                    // If it is a simulation, we simply revert with the full error.
                    if simulationFlags {
                        returndatacopy(mload(0x40), 0x00, returndatasize())
                        revert(mload(0x40), returndatasize())
                    }

                    // If we don't get an error selector, then we set this one.
                    if iszero(err) { err := shl(224, 0xad4db224) } // `VerifiedCallError()`.
                }
            }
        }

        emit UserOpExecuted(u.eoa, u.nonce, selfCallSuccess, err);
        if (selfCallSuccess) {
            gUsed = Math.rawSub(gStart, gasleft());
        }
    }

    /// @dev This function is only intended for self-call.
    /// The name is mined to give a function selector of `0x00000000`, which makes it
    /// more efficient to call by placing it at the leftmost part of the function dispatch tree.
    ///
    /// We perform a gas-limited self-call to this function via `_execute(bytes,uint256)`
    /// with assembly for the following reasons:
    /// - Allow recovery from out-of-gas errors.
    ///   When a transaction is actually mined, an `executionData` payload that takes 100k gas
    ///   to execute during simulation might require 1M gas to actually execute
    ///   (e.g. a sale contract that auto-distributes tokens at the very last sale).
    ///   If we do simply let this consume all gas, then the relayer's compensation
    ///   which is determined to be sufficient during simulation might not be actually sufficient.
    ///   We can only know how much gas a payload costs by actually executing it, but once it
    ///   has been executed, the gas burned cannot be returned and will be debited from the relayer.
    /// - Avoid the overheads of `abi.encode`, `abi.decode`, and memory allocation.
    ///   Doing `(bool success, bytes memory result) = address(this).call(abi.encodeCall(...))`
    ///   incurs unnecessary ABI encoding, decoding, and memory allocation.
    ///   Quadratic memory expansion costs will make UserOps in later parts of a batch
    ///   unfairly punished, while making gas estimates unreliable.
    /// - For even more efficiency, we directly rip the UserOp from the calldata instead
    ///   of making it as an argument to this function.
    ///
    /// This function reverts if the PREP initialization or the UserOp validation fails.
    /// This is to prevent incorrect compensation (the UserOp's signature defines what is correct).
    function selfCallPayVerifyCall537021665() public payable {
        require(msg.sender == address(this));

        UserOp calldata u;
        uint256 simulationFlags;
        assembly ("memory-safe") {
            u := add(0x24, calldataload(0x24))
            simulationFlags := calldataload(0x04)
        }
        address eoa = u.eoa;
        // Verify the nonce, early reverting to save gas.
        (LibStorage.Ref storage seqRef, uint256 seq) =
            LibNonce.check(_getEntryPointStorage().nonceSeqs[eoa], u.nonce);

        // The chicken and egg problem:
        // A off-chain simulation of a successful UserOp may not guarantee on-chain success.
        // The state may change in the window between simulation and actual on-chain execution.
        // If on-chain execution fails, gas that has already been burned cannot be returned
        // and will be debited from the relayer.
        // Yet, we still need to minimally check that the UserOp has a valid signature to draw
        // compensation. If we draw compensation first and then realize that the signature is
        // invalid, we will need to refund the compensation, which is more inefficient than
        // simply ensuring validity of the signature before drawing compensation.
        // The best we can do is to minimize the chance that an UserOp success in off-chain
        // simulation can somehow result in an uncompensated on-chain failure.
        // This is why ERC4337 has all those weird storage and opcode restrictions for
        // simulation, and suggests banning users that intentionally grief the simulation.

        // If `initializePREP` fails, just revert.
        // Off-chain simulation can ensure that the eoa is indeed a PREP address.
        // If the eoa is a PREP address, this means the delegation cannot be altered
        // while the UserOp is in-flight, which means off-chain simulation success
        // guarantees on-chain execution success.
        if (u.initData.length != 0) {
            bytes calldata initData = u.initData;
            assembly ("memory-safe") {
                let m := mload(0x40)
                mstore(m, 0x36745d10) // `initializePREP(bytes)`.
                mstore(add(m, 0x20), 0x20)
                mstore(add(m, 0x40), initData.length)
                calldatacopy(add(m, 0x60), initData.offset, initData.length)
                let success :=
                    call(gas(), eoa, 0, add(m, 0x1c), add(0x64, initData.length), m, 0x20)
                if iszero(and(eq(mload(m), 1), success)) {
                    if simulationFlags {
                        returndatacopy(mload(0x40), 0x00, returndatasize())
                        revert(mload(0x40), returndatasize())
                    }
                    revert(0x00, 0x20)
                }
            }
        }
        // Handle the sub UserOps after the PREP (if any), and before the `_verify`.
        if (u.encodedPreOps.length != 0) _handlePreOps(eoa, simulationFlags, u.encodedPreOps);

        // If `_verify` is invalid, just revert.
        // The verification gas is determined by `executionData` and the delegation logic.
        // Off-chain simulation of `_verify` should suffice, provided that the eoa's
        // delegation is not changed, and the `keyHash` is not revoked
        // in the window between off-chain simulation and on-chain execution.
        (bool isValid, bytes32 keyHash, bytes32 digest) = _verify(u);

        if (simulationFlags == 1) {
            isValid = true;
        }
        if (!isValid) revert VerificationError();

        // PrePayment
        // If `_pay` fails, just revert.
        // Off-chain simulation of `_pay` should suffice,
        // provided that the token balance does not decrease in the window between
        // off-chain simulation and on-chain execution.
        if (u.prePaymentAmount != 0) _pay(u.prePaymentAmount, keyHash, digest, u);

        // Once the payment has been made, the nonce must be invalidated.
        // Otherwise, an attacker can keep replaying the UserOp to take payment and drain the user.
        // EntryPoint UserOp nonce bookkeeping is stored on the EntryPoint itself
        // to make implementing this nonce-invalidation pattern more performant.
        seqRef.value = Math.rawAdd(seq, 1);

        // Equivalent Solidity code:
        // try this.selfCallExecutePay(simulationFlags, keyHash, u) {}
        // catch {
        //     assembly ("memory-safe") {
        //         returndatacopy(0x00, 0x00, 0x20)
        //         return(0x00, 0x20)
        //     }
        // }
        // Gas Savings:
        // ~2.5k gas for general cases, by using existing calldata from the previous self call + avoiding solidity external call overhead.
        assembly ("memory-safe") {
            let m := mload(0x40) // Load the free memory pointer
            mstore(0x00, 0) // Zeroize the return slot.
            mstore(m, 0x759417a8) // `selfCallExecutePay()`
            mstore(add(m, 0x20), simulationFlags) // Add simulationFlags as first param
            mstore(add(m, 0x40), keyHash) // Add keyHash as second param
            mstore(add(m, 0x60), digest) // Add digest as third param

            let encodedUserOpLength := sub(calldatasize(), 0x24)
            // NOTE: The userOp encoding here is non standard, because the data offset does not start from the beginning of the calldata.
            // The data offset starts from the location of the userOp offset itself. The decoding is done accordingly in the receiving function.
            // TODO: Make the userOp encoding standard.
            calldatacopy(add(m, 0x80), 0x24, encodedUserOpLength) // Add userOp starting from the fourth param.

            // We call the selfCallExecutePay function with all the remaining gas,
            // because `selfCallPayVerifyCall537021665` is already gas-limited to the combined gas specified in the UserOp.
            // We don't revert if the selfCallExecutePay reverts,
            // Because we don't want to return the prePayment, since the relay has already paid for the gas.
            // TODO: Should we add some identifier here, either using a return flag, or an event, that informs the caller that execute/post-payment has failed.
            if iszero(
                call(gas(), address(), 0, add(m, 0x1c), add(0x44, encodedUserOpLength), m, 0x20)
            ) {
                if simulationFlags {
                    returndatacopy(mload(0x40), 0x00, returndatasize())
                    revert(mload(0x40), returndatasize())
                }
                return(m, 0x20)
            }
        }
    }

    /// @dev This function is only intended for self-call.
    /// We use this function to call the delegation.execute function, and then the delegation.pay function for post-payment.
    /// Self-calling this function ensures, that if the post payment reverts, then the execute function will also revert.
    function selfCallExecutePay() public payable {
        require(msg.sender == address(this));

        uint256 simulationFlags;
        bytes32 keyHash;
        bytes32 digest;
        UserOp calldata u;

        assembly ("memory-safe") {
            simulationFlags := calldataload(0x04)
            keyHash := calldataload(0x24)
            digest := calldataload(0x44)
            // Non standard decoding of the userOp.
            u := add(0x64, calldataload(0x64))
        }
        address eoa = u.eoa;

        // This re-encodes the ERC7579 `executionData` with the optional `opData`.
        // We expect that the delegation supports ERC7821
        // (an extension of ERC7579 tailored for 7702 accounts).
        bytes memory data = LibERC7579.reencodeBatchAsExecuteCalldata(
            hex"01000000000078210001", // ERC7821 batch execution mode.
            u.executionData,
            abi.encode(keyHash) // `opData`.
        );

        assembly ("memory-safe") {
            mstore(0x00, 0) // Zeroize the return slot.
            if iszero(call(gas(), eoa, 0, add(0x20, data), mload(data), 0x00, 0x20)) {
                if simulationFlags {
                    returndatacopy(mload(0x40), 0x00, returndatasize())
                    revert(mload(0x40), returndatasize())
                }
                if iszero(mload(0x00)) { mstore(0x00, shl(224, 0x6c9d47e8)) } // `CallError()`.
                revert(0x00, 0x20) // Revert with the `err`.
            }
        }

        uint256 remainingPaymentAmount = u.totalPaymentAmount - u.prePaymentAmount;
        if (remainingPaymentAmount != 0) {
            _pay(remainingPaymentAmount, keyHash, digest, u);
        }

        assembly ("memory-safe") {
            mstore(0x00, 0) // Zeroize the return slot.
            return(0x00, 0x20) // If all success, returns with zero `err`.
        }
    }

    /// @dev Loops over the `encodedPreOps` and does the following for each:
    /// - If the `eoa == address(0)`, it will be coalesced to `parentEOA`.
    /// - Check if `eoa == parentEOA`.
    /// - Validate the signature.
    /// - Check and increment the nonce, if it is not `type(uint256).max`.
    /// - Call the Delegation with `executionData`, using the ERC7821 batch-execution mode.
    ///   If the call fails, revert.
    /// - Emit an {UserOpExecuted} event, if `nonce` is not `type(uint256).max`.
    function _handlePreOps(
        address parentEOA,
        uint256 simulationFlags,
        bytes[] calldata encodedPreOps
    ) internal virtual {
        for (uint256 i; i < encodedPreOps.length; ++i) {
            PreOp calldata p = _extractPreOp(encodedPreOps[i]);
            address eoa = Math.coalesce(p.eoa, parentEOA);
            uint256 nonce = p.nonce;

            if (eoa != parentEOA) revert InvalidPreOpEOA();

            (bool isValid, bytes32 keyHash,) = _verify(u);
            if (simulationFlags == 1) {
                isValid = true;
            }
            if (!isValid) revert PreOpVerificationError();

            if (nonce != type(uint256).max) {
                LibNonce.checkAndIncrement(_getEntryPointStorage().nonceSeqs[eoa], nonce);
            }

            // This part is same as `selfCallPayVerifyCall537021665`. We simply inline to save gas.
            bytes memory data = LibERC7579.reencodeBatchAsExecuteCalldata(
                hex"01000000000078210001", // ERC7821 batch execution mode.
                p.executionData,
                abi.encode(keyHash) // `opData`.
            );
            // This part is slightly different from `selfCallPayVerifyCall537021665`.
            // It always reverts on failure.
            assembly ("memory-safe") {
                mstore(0x00, 0) // Zeroize the return slot.
                if iszero(call(gas(), eoa, 0, add(0x20, data), mload(data), 0x00, 0x20)) {
                    // If this is a simulation via `simulateFailed`, bubble up the whole revert.
                    if simulationFlags {
                        returndatacopy(mload(0x40), 0x00, returndatasize())
                        revert(mload(0x40), returndatasize())
                    }
                    if iszero(mload(0x00)) { mstore(0x00, shl(224, 0x253e076a)) } // `PreOpCallError()`.
                    revert(0x00, 0x20) // Revert the `err` (NOT return).
                }
            }

            if (nonce != type(uint256).max) {
                // Event so that indexers can know that the nonce is used.
                // Reaching here means there's no error in the PreOp.
                emit UserOpExecuted(eoa, nonce, true, 0); // `incremented = true`, `err = 0`.
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // Delegation Implementation
    ////////////////////////////////////////////////////////////////////////

    /// @dev Returns the implementation of the EOA.
    /// If the EOA's delegation's is not valid EIP7702Proxy (via bytecode check), returns `address(0)`.
    /// This function is provided as a public helper for easier integration.
    function delegationImplementationOf(address eoa) public view virtual returns (address result) {
        (, result) = LibEIP7702.delegationAndImplementationOf(eoa);
    }

    ////////////////////////////////////////////////////////////////////////
    // Nonces
    ////////////////////////////////////////////////////////////////////////

    /// @dev Return current nonce with sequence key.
    function getNonce(address eoa, uint192 seqKey) public view virtual returns (uint256) {
        return LibNonce.get(_getEntryPointStorage().nonceSeqs[eoa], seqKey);
    }

    /// @dev Increments the sequence for the `seqKey` in nonce (i.e. upper 192 bits).
    /// This invalidates the nonces for the `seqKey`, up to (inclusive) `uint64(nonce)`.
    function invalidateNonce(uint256 nonce) public virtual {
        LibNonce.invalidate(_getEntryPointStorage().nonceSeqs[msg.sender], nonce);
        emit NonceInvalidated(msg.sender, nonce);
    }

    ////////////////////////////////////////////////////////////////////////
    // ERC7683
    ////////////////////////////////////////////////////////////////////////

    /// @dev ERC7683 fill.
    /// If you don't need to ensure that the `orderId` can only be used once,
    /// pass in `bytes32(0)` for the `orderId`. The `originData` will
    /// already include the nonce for the delegated `eoa`.
    function fill(bytes32 orderId, bytes calldata originData, bytes calldata)
        public
        payable
        virtual
        returns (bytes4)
    {
        if (orderId != bytes32(0)) {
            if (!_getEntryPointStorage().filledOrderIds.toggle(uint256(orderId))) {
                revert OrderAlreadyFilled();
            }
        }
        // Like `abi.decode(originData, (bytes, address, uint256))`, but way faster.
        if (originData.length < 0x60) revert();
        bytes calldata encodedUserOp = LibBytes.bytesInCalldata(originData, 0x00);
        address fundingToken = address(uint160(uint256(LibBytes.loadCalldata(originData, 0x20))));
        uint256 fundingAmount = uint256(LibBytes.loadCalldata(originData, 0x40));

        // Like `abi.decode(encodedUserOp, (UserOp)).eoa`, but way faster.
        bytes calldata u = LibBytes.dynamicStructInCalldata(encodedUserOp, 0x00);
        address eoa = address(uint160(uint256(LibBytes.loadCalldata(u, 0x00))));

        TokenTransferLib.safeTransferFrom(fundingToken, msg.sender, eoa, fundingAmount);
        return execute(encodedUserOp);
    }

    /// @dev Returns true if the order ID has been filled.
    function orderIdIsFilled(bytes32 orderId) public view virtual returns (bool) {
        if (orderId == bytes32(0)) return false;
        return _getEntryPointStorage().filledOrderIds.get(uint256(orderId));
    }

    ////////////////////////////////////////////////////////////////////////
    // Internal Helpers
    ////////////////////////////////////////////////////////////////////////

    /// @dev Makes the `eoa` perform a payment to the `paymentRecipient` directly.
    /// This reverts if the payment is insufficient or fails. Otherwise returns nothing.
    function _pay(uint256 paymentAmount, bytes32 keyHash, bytes32 digest, UserOp calldata u)
        internal
        virtual
    {
        uint256 requiredBalanceAfter = Math.saturatingAdd(
            TokenTransferLib.balanceOf(u.paymentToken, u.paymentRecipient), paymentAmount
        );

        address payer = Math.coalesce(u.payer, u.eoa);

        // Call the pay function on the delegation contract
        // Equivalent Solidity code:
        // IDelegation(payer).pay(paymentAmount, keyHash, abi.encode(u));
        // Gas Savings:
        // Saves ~2k gas for normal use cases, by avoiding abi.encode and solidity external call overhead
        assembly ("memory-safe") {
            let m := mload(0x40) // Load the free memory pointer
            mstore(m, 0xf81d87a7) // `pay(uint256,bytes32,bytes32,bytes)`
            mstore(add(m, 0x20), paymentAmount) // Add payment amount as first param
            mstore(add(m, 0x40), keyHash) // Add keyHash as second param
            mstore(add(m, 0x60), digest) // Add digest as third param
            mstore(add(m, 0x80), 0x80) // Add offset of encoded UserOp as third param

            let encodedSize := sub(calldatasize(), u)

            mstore(add(m, 0xa0), add(encodedSize, 0x20)) // Store length of encoded UserOp at offset.
            mstore(add(m, 0xc0), 0x20) // Offset at which the UserOp struct starts in encoded UserOp.

            // Copy the userOp data to memory
            calldatacopy(add(m, 0xe0), u, encodedSize)

            // TODO: If pay reverts, we now send a revert back instead of ignoring. This is a breaking change, add to changeset.
            if iszero(
                call(
                    gas(), // gas
                    payer, // address
                    0, // value
                    add(m, 0x1c), // input memory offset
                    add(0xc4, encodedSize), // input size
                    0x00, // output memory offset
                    0x20 // output size
                )
            ) { revert(0x00, 0x20) }
        }

        if (TokenTransferLib.balanceOf(u.paymentToken, u.paymentRecipient) < requiredBalanceAfter) {
            revert PaymentError();
        }
    }

    /// @dev Calls `unwrapAndValidateSignature` on the `eoa`.
    function _verify(bytes32 digest, address eoa, bytes calldata sig)
        internal
        view
        virtual
        returns (bool isValid, bytes32 keyHash)
    {
        // While it is technically safe for the digest to be computed on the delegation,
        // we do it on the EntryPoint for efficiency and maintainability. Validating the
        // a single bytes32 digest avoids having to pass in the entire UserOp. Additionally,
        // the delegation does not need to know anything about the UserOp structure.
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 0x0cef73b4) // `unwrapAndValidateSignature(bytes32,bytes)`.
            mstore(add(m, 0x20), digest)
            mstore(add(m, 0x40), 0x40)
            mstore(add(m, 0x60), sig.length)
            calldatacopy(add(m, 0x80), sig.offset, sig.length)
            isValid := staticcall(gas(), eoa, add(m, 0x1c), add(sig.length, 0x64), 0x00, 0x40)
            isValid := and(eq(mload(0x00), 1), and(gt(returndatasize(), 0x3f), isValid))
            keyHash := mload(0x20)
        }
    }

    /// @dev Computes the EIP712 digest for the PreOp.
    function _computeDigest(PreOp calldata p) internal view virtual returns (bytes32) {
        bool isMultichain = p.nonce >> 240 == MULTICHAIN_NONCE_PREFIX;
        // To avoid stack-too-deep. Faster than a regular Solidity array anyways.
        bytes32[] memory f = EfficientHashLib.malloc(5);
        f.set(0, PRE_OP_TYPEHASH);
        f.set(1, LibBit.toUint(isMultichain));
        f.set(2, uint160(p.eoa));
        f.set(3, _executionDataHash(p.executionData));
        f.set(4, p.nonce);

        return isMultichain ? _hashTypedDataSansChainId(f.hash()) : _hashTypedData(f.hash());
    }

    /// @dev Computes the EIP712 digest for the UserOp.
    /// If the the nonce starts with `MULTICHAIN_NONCE_PREFIX`,
    /// the digest will be computed without the chain ID.
    /// Otherwise, the digest will be computed with the chain ID.
    function _computeDigest(UserOp calldata u) internal view virtual returns (bytes32) {
        bool isMultichain = u.nonce >> 240 == MULTICHAIN_NONCE_PREFIX;
        // To avoid stack-too-deep. Faster than a regular Solidity array anyways.
        bytes32[] memory f = EfficientHashLib.malloc(11);
        f.set(0, USER_OP_TYPEHASH);
        f.set(1, LibBit.toUint(isMultichain));
        f.set(2, uint160(u.eoa));
        f.set(3, _executionDataHash(u.executionData));
        f.set(4, u.nonce);
        f.set(5, uint160(u.payer));
        f.set(6, uint160(u.paymentToken));
        f.set(7, u.paymentMaxAmount);
        f.set(8, u.paymentPerGas);
        f.set(9, u.combinedGas);
        f.set(10, _encodedPreOpsHash(u.encodedPreOps));

        return isMultichain ? _hashTypedDataSansChainId(f.hash()) : _hashTypedData(f.hash());
    }

    /// @dev Helper function to return the hash of the `execuctionData`.
    function _executionDataHash(bytes calldata executionData)
        internal
        view
        virtual
        returns (bytes32)
    {
        bytes32[] calldata pointers = LibERC7579.decodeBatch(executionData);
        bytes32[] memory a = EfficientHashLib.malloc(pointers.length);
        unchecked {
            for (uint256 i; i != pointers.length; ++i) {
                (address target, uint256 value, bytes calldata data) = pointers.getExecution(i);
                a.set(
                    i,
                    EfficientHashLib.hash(
                        CALL_TYPEHASH,
                        bytes32(uint256(uint160(target))),
                        bytes32(value),
                        EfficientHashLib.hashCalldata(data)
                    )
                );
            }
        }
        return a.hash();
    }

    /// @dev Helper function to return the hash of the `encodedPreOps`.
    function _encodedPreOpsHash(bytes[] calldata encodedPreOps)
        internal
        view
        virtual
        returns (bytes32)
    {
        bytes32[] memory a = EfficientHashLib.malloc(encodedPreOps.length);
        for (uint256 i; i < encodedPreOps.length; ++i) {
            a.set(i, EfficientHashLib.hashCalldata(encodedPreOps[i]));
        }
        return a.hash();
    }

    receive() external payable virtual {}

    ////////////////////////////////////////////////////////////////////////
    // Only Owner Functions
    ////////////////////////////////////////////////////////////////////////

    /// @dev Allows the entry point owner to withdraw tokens.
    /// If `token` is `address(0)`, withdraws the native gas token.
    function withdrawTokens(address token, address recipient, uint256 amount)
        public
        virtual
        onlyOwner
    {
        TokenTransferLib.safeTransfer(token, recipient, amount);
    }

    ////////////////////////////////////////////////////////////////////////
    // EIP712
    ////////////////////////////////////////////////////////////////////////

    /// @dev For EIP712.
    function _domainNameAndVersion()
        internal
        view
        virtual
        override
        returns (string memory name, string memory version)
    {
        name = "EntryPoint";
        version = "0.0.3";
    }

    ////////////////////////////////////////////////////////////////////////
    // Other Overrides
    ////////////////////////////////////////////////////////////////////////

    /// @dev There won't be chains that have 7702 and without TSTORE.
    function _useTransientReentrancyGuardOnlyOnMainnet()
        internal
        view
        virtual
        override
        returns (bool)
    {
        return false;
    }
}
