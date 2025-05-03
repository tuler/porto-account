// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./utils/SoladyTest.sol";
import "./Base.t.sol";
import "../src/DeployAll.sol";

contract LibPREPTest is SoladyTest {
    function testDeployAll() public {
        DeployAll deployAll = new DeployAll();

        address entryPoint = deployAll.entryPoint();

        assertEq(
            Delegation(payable(deployAll.delegationImplementation())).ENTRY_POINT(), entryPoint
        );

        address eoa = _randomUniqueHashedAddress();

        vm.etch(eoa, abi.encodePacked(hex"ef0100", deployAll.delegationImplementation()));
        assertEq(Delegation(payable(eoa)).ENTRY_POINT(), entryPoint);

        vm.etch(eoa, abi.encodePacked(hex"ef0100", deployAll.delegationProxy()));
        assertEq(Delegation(payable(eoa)).ENTRY_POINT(), entryPoint);
    }
}
