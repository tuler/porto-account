// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {P256BatchDelegation} from "../src/P256BatchDelegation.sol";
import {P256} from "../src/utils/P256.sol";
import {ECDSA} from "../src/utils/ECDSA.sol";

contract Callee {
    error UnexpectedSender(address expected, address actual);

    mapping(address => uint256) public counter;
    mapping(address => uint256) public values;

    function increment() public payable {
        counter[msg.sender] += 1;
        values[msg.sender] += msg.value;
    }

    function expectSender(address expected) public payable {
        if (msg.sender != expected) {
            revert UnexpectedSender(expected, msg.sender);
        }
    }
}

contract P256BatchDelegationTest is Test {
    P256BatchDelegation public delegation;
    uint256 public p256PrivateKey;
    Callee public callee;

    function setUp() public {
        callee = new Callee();
        delegation = new P256BatchDelegation();
        p256PrivateKey = 100366595829038452957523597440756290436854445761208339940577349703440345778405;
        vm.deal(address(delegation), 1.5 ether);
    }

    function test_authorize() public {
        vm.pauseGasMetering();

        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);
        ECDSA.PublicKey memory publicKey = ECDSA.PublicKey(x, y);

        vm.expectRevert();
        delegation.delegates(0);

        vm.prank(address(delegation));
        vm.resumeGasMetering();
        delegation.authorize(publicKey);
        vm.pauseGasMetering();

        (uint256 authorizedX, uint256 authorizedY) = delegation.delegates(0);
        assertEq(authorizedX, publicKey.x);
        assertEq(authorizedY, publicKey.y);
    }

    function test_revoke() public {
        vm.pauseGasMetering();

        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);
        ECDSA.PublicKey memory publicKey = ECDSA.PublicKey(x, y);

        vm.prank(address(delegation));
        delegation.authorize(publicKey);

        delegation.delegates(0);

        vm.prank(address(delegation));
        vm.resumeGasMetering();
        delegation.revoke(0);
        vm.pauseGasMetering();

        vm.expectRevert();
        delegation.delegates(0);
    }

    function test_executeWithDelegate() public {
        vm.pauseGasMetering();

        assertEq(address(delegation).balance, 1.5 ether);
        assertEq(address(callee).balance, 0 ether);

        bytes memory data = abi.encodeWithSelector(Callee.increment.selector);
        bytes memory calls;
        calls = abi.encodePacked(uint8(0), address(callee), uint256(0.5 ether), data.length, data);
        calls = abi.encodePacked(calls, uint8(0), address(callee), uint256(0.5 ether), data.length, data);
        calls = abi.encodePacked(calls, uint8(0), address(callee), uint256(0.5 ether), data.length, data);

        bytes32 hash = keccak256(abi.encodePacked(delegation.executeNonce(), calls));
        (bytes32 r, bytes32 s) = vm.signP256(p256PrivateKey, hash);
        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);

        vm.prank(address(delegation));
        delegation.authorize(ECDSA.PublicKey(x, y));

        vm.resumeGasMetering();
        delegation.executeWithDelegate(calls, ECDSA.Signature(uint256(r), uint256(s)), 0, false);
        vm.pauseGasMetering();

        assertEq(callee.counter(address(delegation)), 3);
        assertEq(callee.values(address(delegation)), 1.5 ether);
        assertEq(address(delegation).balance, 0 ether);
        assertEq(address(callee).balance, 1.5 ether);
    }

    function test_revert_replay() public {
        vm.pauseGasMetering();

        bytes memory data = abi.encodeWithSelector(Callee.increment.selector);
        bytes memory calls;
        calls = abi.encodePacked(uint8(0), address(callee), uint256(0), data.length, data);
        calls = abi.encodePacked(calls, uint8(0), address(callee), uint256(0), data.length, data);
        calls = abi.encodePacked(calls, uint8(0), address(callee), uint256(0), data.length, data);

        bytes32 hash = keccak256(abi.encodePacked(delegation.executeNonce(), calls));
        (bytes32 r, bytes32 s) = vm.signP256(p256PrivateKey, hash);
        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);

        vm.prank(address(delegation));
        delegation.authorize(ECDSA.PublicKey(x, y));

        vm.resumeGasMetering();
        delegation.executeWithDelegate(calls, ECDSA.Signature(uint256(r), uint256(s)), 0, false);
        vm.pauseGasMetering();

        vm.expectRevert(P256BatchDelegation.InvalidSignature.selector);
        delegation.executeWithDelegate(calls, ECDSA.Signature(uint256(r), uint256(s)), 0, false);
    }

    function test_revert_revokeAuth() public {
        vm.pauseGasMetering();

        bytes memory data = abi.encodeWithSelector(Callee.increment.selector);
        bytes memory calls;
        calls = abi.encodePacked(uint8(0), address(callee), uint256(0), data.length, data);
        calls = abi.encodePacked(calls, uint8(0), address(callee), uint256(0), data.length, data);
        calls = abi.encodePacked(calls, uint8(0), address(callee), uint256(0), data.length, data);

        bytes32 hash = keccak256(abi.encodePacked(delegation.executeNonce(), calls));
        (bytes32 r, bytes32 s) = vm.signP256(p256PrivateKey, hash);
        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);

        vm.prank(address(delegation));
        delegation.authorize(ECDSA.PublicKey(x, y));

        vm.prank(address(delegation));
        vm.resumeGasMetering();
        delegation.revoke(0);
        vm.pauseGasMetering();

        vm.expectRevert();
        delegation.executeWithDelegate(calls, ECDSA.Signature(uint256(r), uint256(s)), 0, false);
    }
}
