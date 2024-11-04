// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ECDSA} from "../../src/utils/ECDSA.sol";
import {P256} from "../../src/utils/P256.sol";
import {WebAuthnP256} from "../../src/utils/WebAuthnP256.sol";

contract WebAuthnP256Test is Test {
    bytes32 challenge = hex"f631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf";

    ECDSA.PublicKey public publicKey = ECDSA.PublicKey(
        15325272481743543470187210372131079389379804084126119117911265853867256769440,
        74947999673872536163854436677160946007685903587557427331495653571111132132212
    );

    WebAuthnP256.Metadata public metadata = WebAuthnP256.Metadata(
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000",
        '{"type":"webauthn.get","challenge":"9jEFijuhEWrM4SOW-tChJbUEHEP44VcjcJ-Bqo1fTM8","origin":"http://localhost:5173","crossOrigin":false}',
        23,
        1,
        true
    );

    function test_verify() public view {
        ECDSA.Signature memory signature = ECDSA.Signature(
            10330677067519063752777069525326520293658884904426299601620960859195372963151,
            47017859265388077754498411591757867926785106410894171160067329762716841868244
        );
        bool res = WebAuthnP256.verify(challenge, metadata, signature, publicKey);
        assertEq(res, true);
    }
}
