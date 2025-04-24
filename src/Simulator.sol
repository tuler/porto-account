// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ICommon} from "./interfaces/ICommon.sol";
import {FixedPointMathLib as Math} from "solady/utils/FixedPointMathLib.sol";

contract Simulator {
    function _updatePaymentAmounts(
        ICommon.UserOp memory u,
        bool isPrePayment,
        uint256 gasUsed,
        uint256 paymentPerGas
    ) internal pure {
        uint256 paymentAmount = gasUsed * paymentPerGas;

        if (isPrePayment) {
            u.prePaymentAmount += paymentAmount;
            u.prePaymentMaxAmount += paymentAmount;
        }

        u.totalPaymentAmount += paymentAmount;
        u.totalPaymentMaxAmount += paymentAmount;
    }

    function _callEntryPointCalldata(
        address ep,
        bool isStateOverride,
        uint256 combinedGasOverride,
        bytes calldata encodedUserOp
    ) internal returns (uint256 gasUsed) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 0x91210ad3) // function selector of `simulateExecute(bool,uint256,bytes)`
            mstore(add(m, 0x20), isStateOverride)
            mstore(add(m, 0x40), combinedGasOverride) // During the primary run, the combinedGasOverride is type(uint256).max
            mstore(add(m, 0x60), 0x60) // encodedUserOp
            mstore(add(m, 0x80), encodedUserOp.length)
            calldatacopy(add(m, 0xa0), encodedUserOp.offset, encodedUserOp.length)

            // Zeroize return slots
            mstore(0x00, 0)
            mstore(0x20, 0)

            let success :=
                call(gas(), ep, 0, add(m, 0x1c), add(encodedUserOp.length, 0x84), 0x00, 0x20)

            // Success should only happen if isStateOverride is true
            if isStateOverride {
                if success {
                    // Return gasUsed
                    gasUsed := mload(0x00)
                }
            }
            // If not state override, check for SimulationPassed selector
            if iszero(isStateOverride) {
                let err := shr(224, mload(0x00))
                // Check if first 4 bytes are equal to SimulationPassed(uint256)
                if eq(err, 0x4f0c028c) {
                    returndatacopy(0x00, 0x04, 0x20)
                    // Execute was successful
                    gasUsed := mload(0x00)
                }
            }
        }
    }

    function _callEntryPointMemory(
        address ep,
        bool isStateOverride,
        uint256 combinedGasOverride,
        ICommon.UserOp memory u
    ) internal returns (uint256 gasUsed) {
        uint256 mCache;
        // Cache the free memory pointer
        assembly ("memory-safe") {
            mCache := mload(0x40)
        }

        bytes memory encodedUserOp = abi.encode(u);

        // Set the simulation flag to true
        assembly ("memory-safe") {
            let m := mload(0x40)

            mstore(m, 0x91210ad3) // function selector of `simulateExecute(bool,uint256,bytes)`
            mstore(add(m, 0x20), isStateOverride)
            mstore(add(m, 0x40), combinedGasOverride) // During the verification run, the combinedGasOverride is 0.
            mstore(add(m, 0x60), 0x60) // encodedUserOp
            let len := mload(encodedUserOp)
            mcopy(add(m, 0x80), encodedUserOp, len)

            // Zeroize return slots
            mstore(0x00, 0)
            mstore(0x20, 0)

            let success := call(gas(), ep, 0, add(m, 0x1c), add(len, 0x84), 0x00, 0x20)

            // Success should only happen if isStateOverride is true
            if isStateOverride {
                if success {
                    // Return gasUsed
                    gasUsed := mload(0x00)
                }
            }
            // If not state override, check for SimulationPassed selector
            if iszero(isStateOverride) {
                let err := shr(224, mload(0x00))
                // Check if first 4 bytes are equal to SimulationPassed(uint256)
                if eq(err, 0x4f0c028c) {
                    returndatacopy(0x00, 0x04, 0x20)
                    // Execute was successful
                    gasUsed := mload(0x00)
                }
            }
        }

        // Restore the free memory pointer
        // We do this so that abi.encode doesn't keep expanding memory, when used in a loop
        assembly ("memory-safe") {
            mstore(0x40, mCache)
        }
    }

    /// @dev Simulate the gas usage for a user operation. This function reverts if the simulation fails.
    /// @param ep The entry point address
    /// @param overrideCombinedGas Whether to override the combined gas for the userOp to type(uint256).max
    /// @param encodedUserOp The encoded user operation
    /// @return gasUsed The amount of gas used by the simulation
    function simulateGasUsed(address ep, bool overrideCombinedGas, bytes calldata encodedUserOp)
        public
        payable
        virtual
        returns (uint256 gasUsed)
    {
        gasUsed = _callEntryPointCalldata(
            ep, false, overrideCombinedGas ? type(uint256).max : 0, encodedUserOp
        );

        // If the simulation failed, bubble up full revert
        assembly ("memory-safe") {
            if iszero(gasUsed) {
                let m := mload(0x40)
                returndatacopy(m, 0x00, returndatasize())
                revert(m, returndatasize())
            }
        }
    }

    /// @dev Simulates the execution of a userOp, and finds the combined gas by iteratively increasing it until the simulation passes.
    /// The start value for combinedGas is gasUsed + original combinedGas.
    /// Set u.combinedGas to add some starting offset to the gasUsed value.
    /// @param ep The entry point address
    /// @param isPrePayment Whether to add gas amount to prePayment or postPayment
    /// @param paymentPerGas The amount of `paymentToken` to be added per gas unit.
    /// Total payment is calculated as pre/postPaymentAmount += gasUsed * paymentPerGas.
    /// @dev Set prePayment or totalPaymentAmount to include any static offset to the gas value.
    /// @param combinedGasIncrement Basis Points increment to be added for each iteration of searching for combined gas.
    /// @dev The closer this number is to 10_000, the more precise combined gas will be. But more iterations will be needed.
    /// @dev This number should always be > 10_000, to get correct results.
    //// If the increment is too small, the function might run out of gas while finding the combined gas value.
    /// @param encodedUserOp The encoded user operation
    /// @return gasUsed The gas used in the successful simulation
    /// @return combinedGas The first combined gas value that gives a successful simulation.
    /// This function reverts if the primary simulation run with max combinedGas fails.
    /// If the primary run is successful, it itertively increases u.combinedGas by `combinedGasIncrement` until the simulation passes.
    /// All failing simulations during this run are ignored.
    function simulateCombinedGas(
        address ep,
        bool isPrePayment,
        uint256 paymentPerGas,
        uint256 combinedGasIncrement,
        bytes calldata encodedUserOp
    ) public payable virtual returns (uint256 gasUsed, uint256 combinedGas) {
        // 1. Primary Simulation Run to get initial gasUsed value with combinedGasOverride
        gasUsed = _callEntryPointCalldata(ep, false, type(uint256).max, encodedUserOp);

        // If the simulation failed, bubble up full revert
        assembly ("memory-safe") {
            if iszero(gasUsed) {
                let m := mload(0x40)
                returndatacopy(m, 0x00, returndatasize())
                revert(m, returndatasize())
            }
        }

        // Update payment amounts using the gasUsed value
        ICommon.UserOp memory u = abi.decode(encodedUserOp, (ICommon.UserOp));

        uint256 paymentAmount = gasUsed * paymentPerGas;

        if (isPrePayment) {
            u.prePaymentAmount += paymentAmount;
            u.prePaymentMaxAmount += paymentAmount;
        }

        u.totalPaymentAmount += paymentAmount;
        u.totalPaymentMaxAmount += paymentAmount;

        u.combinedGas += gasUsed;

        while (true) {
            gasUsed = _callEntryPointMemory(ep, false, 0, u);

            if (gasUsed != 0) {
                return (gasUsed, u.combinedGas);
            }

            // Step up the combined gas, until we see a simulation passing
            u.combinedGas += Math.mulDiv(u.combinedGas, combinedGasIncrement, 10_000);
        }
    }

    /// @dev Same as simulateCombinedGas, but with an additional verification run
    /// that generates a successful non reverting state override simulation.
    /// Which can be used in eth_simulateV1 to get the trace.\
    /// @dev combinedGasVerificationOffset is a static value that is added after a succesful combinedGas is found.
    /// This can be used to account for variations in sig verification gas, for keytypes like P256.
    function simulateV1Logs(
        address ep,
        bool isPrePayment,
        uint256 paymentPerGas,
        uint256 combinedGasIncrement,
        uint256 combinedGasVerificationOffset,
        bytes calldata encodedUserOp
    ) public payable virtual returns (uint256 gasUsed, uint256 combinedGas) {
        (gasUsed, combinedGas) = simulateCombinedGas(
            ep, isPrePayment, paymentPerGas, combinedGasIncrement, encodedUserOp
        );

        combinedGas += combinedGasVerificationOffset;

        ICommon.UserOp memory u = abi.decode(encodedUserOp, (ICommon.UserOp));

        _updatePaymentAmounts(u, isPrePayment, combinedGas, paymentPerGas);

        u.combinedGas = combinedGas;

        // Verification Run to generate the logs with the correct combinedGas and payment amounts.
        gasUsed = _callEntryPointMemory(ep, true, 0, u);

        // If the simulation failed, bubble up full revert
        assembly ("memory-safe") {
            if iszero(gasUsed) {
                let m := mload(0x40)
                returndatacopy(m, 0x00, returndatasize())
                revert(m, returndatasize())
            }
        }
    }
}
