// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {TaskManager} from "../src/MockTaskManager.sol";
import {EncryptedInput} from "../src/MockCoFHE.sol";
import {ACL} from "../src/ACL.sol";
import {MockZkVerifier} from "../src/MockZkVerifier.sol";
import {MockZkVerifierSigner} from "../src/MockZkVerifierSigner.sol";
import {ZK_VERIFIER_ADDRESS, ZK_VERIFIER_SIGNER_ADDRESS} from "../src/addresses/ZkVerifierAddress.sol";
import {MockQueryDecrypter} from "../src/MockQueryDecrypter.sol";
import {QUERY_DECRYPTER_ADDRESS} from "../src/addresses/QueryDecrypterAddress.sol";
import {TASK_MANAGER_ADDRESS} from "../src/addresses/TaskManagerAddress.sol";

contract DeployMocksScript is Script {
    TaskManager public taskManager;
    MockZkVerifier public zkVerifier;
    MockZkVerifierSigner public zkVerifierSigner;
    ACL public acl;
    MockQueryDecrypter public queryDecrypter;

    modifier broadcast() {
        vm.startBroadcast();
        _;
        vm.stopBroadcast();
    }

    function run() public broadcast {
        bytes memory MockTaskManagerCreationCode = type(TaskManager)
            .creationCode;
        bytes memory MockTaskManagerConstructorArgs = abi.encode(
            address(this),
            0,
            1
        );
        bytes memory MockTaskManagerBytecode = abi.encodePacked(
            MockTaskManagerCreationCode,
            MockTaskManagerConstructorArgs
        );
        vm.etch(TASK_MANAGER_ADDRESS, MockTaskManagerBytecode);
        taskManager = TaskManager(TASK_MANAGER_ADDRESS);

        bytes memory MockZkVerifierCreationCode = type(MockZkVerifier)
            .creationCode;
        vm.etch(ZK_VERIFIER_ADDRESS, MockZkVerifierCreationCode);
        zkVerifier = MockZkVerifier(ZK_VERIFIER_ADDRESS);

        bytes memory MockQueryDecrypterCreationCode = type(MockQueryDecrypter)
            .creationCode;
        vm.etch(QUERY_DECRYPTER_ADDRESS, MockQueryDecrypterCreationCode);
        queryDecrypter = MockQueryDecrypter(QUERY_DECRYPTER_ADDRESS);

        acl = new ACL();
        acl.initialize(address(this));
        taskManager.setACLContract(address(acl));
    }
}
