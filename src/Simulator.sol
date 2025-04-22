// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ICommon} from "./interfaces/ICommon.sol";
import {FixedPointMathLib as Math} from "solady/utils/FixedPointMathLib.sol";

contract Simulator {
    function _getGasUsed() internal pure returns (uint256 gasUsed) {
        assembly ("memory-safe") {
            let err := shl(224, shr(224, mload(0)))
            // Check if first 4 bytes are equal to SimulationPassed(uint256)
            if eq(err, 0x4f0c028c00000000000000000000000000000000000000000000000000000000) {
                // Execute was successful
                gasUsed := mload(0x04)
            }
        }
    }

    function _callEntryPointCalldata(
        address ep,
        uint256 combinedGasOverride,
        bytes calldata encodedUserOp
    ) internal {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 0x68faa9fd) // function selector of simulateExecute
            mstore(add(m, 0x20), combinedGasOverride) // During the primary run, the combinedGasOverride is type(uint256).max
            mstore(add(m, 0x40), 0x40) // encodedUserOp
            mstore(add(m, 0x60), encodedUserOp.length)
            calldatacopy(add(m, 0x80), encodedUserOp.offset, encodedUserOp.length)

            // Zeroize return slots
            mstore(0x00, 0)
            mstore(0x20, 0)

            let success :=
                call(
                    gas(), ep, selfbalance(), add(m, 0x1c), add(encodedUserOp.length, 0x64), 0x00, 0x40
                )

            if success {
                // Simulate Self Call should *always* fail
                revert(0x00, 0x00)
            }
        }
    }

    function _callEntryPointMemory(
        address ep,
        uint256 combinedGasOverride,
        bytes memory encodedUserOp
    ) internal {
        // Set the simulation flag to true
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 0x68faa9fd) // function selector of simulateExecute
            mstore(add(m, 0x20), combinedGasOverride) // During the verification run, the combinedGasOverride is 0.
            mstore(add(m, 0x40), 0x40) // encodedUserOp
            let len := mload(encodedUserOp)
            mcopy(add(m, 0x60), encodedUserOp, len)

            // Zeroize return slots
            mstore(0x00, 0)
            mstore(0x20, 0)

            let success := call(gas(), ep, selfbalance(), add(m, 0x1c), add(len, 0x64), 0x00, 0x40)

            if success {
                // Simulate Self Call should *always* fail
                revert(0x00, 0x00)
            }
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
        _callEntryPointCalldata(ep, overrideCombinedGas ? type(uint256).max : 0, encodedUserOp);

        gasUsed = _getGasUsed();

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
        _callEntryPointCalldata(ep, type(uint256).max, encodedUserOp);

        gasUsed = _getGasUsed();

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
            _callEntryPointMemory(ep, 0, abi.encode(u));

            gasUsed = _getGasUsed();

            if (gasUsed != 0) {
                return (gasUsed, u.combinedGas);
            }

            // Step up the combined gas, until we see a simulation passing
            u.combinedGas += Math.mulDiv(u.combinedGas, combinedGasIncrement, 10_000);
        }
    }
}
