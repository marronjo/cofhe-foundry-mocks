// SPDX-License-Identifier: BSD-3-Clause-Clear
// solhint-disable one-contract-per-file

pragma solidity >=0.8.19 <0.9.0;

import {SIGNER_PRIVATE_KEY, EncryptedInput} from "./MockCoFHE.sol";
import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MockZkVerifierSigner is Test {
    function zkVerifySignPacked(
        EncryptedInput[] memory inputs
    ) public pure returns (EncryptedInput[] memory) {
        EncryptedInput[] memory signedInputs = new EncryptedInput[](
            inputs.length
        );
        for (uint256 i = 0; i < inputs.length; i++) {
            signedInputs[i] = zkVerifySign(inputs[i]);
        }
        return signedInputs;
    }

    function zkVerifySign(
        EncryptedInput memory input
    ) public pure returns (EncryptedInput memory) {
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
            keccak256(
                abi.encodePacked(input.ctHash, input.securityZone, input.utype)
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PRIVATE_KEY, digest);
        bytes memory signature = abi.encodePacked(r, s, v); // note the order here is different from line above.

        input.signature = signature;
        return input;
    }
}
