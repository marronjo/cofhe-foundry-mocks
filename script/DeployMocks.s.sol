// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
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

    function deployCodeTo(string memory what, address where) internal virtual {
        deployCodeTo(what, "", 0, where);
    }

    function deployCodeTo(
        string memory what,
        bytes memory args,
        address where
    ) internal virtual {
        deployCodeTo(what, args, 0, where);
    }

    function deployCodeTo(
        string memory what,
        bytes memory args,
        uint256 value,
        address where
    ) internal virtual {
        bytes memory creationCode = vm.getCode(what);
        vm.etch(where, abi.encodePacked(creationCode, args));
        (bool success, bytes memory runtimeBytecode) = where.call{value: value}(
            ""
        );
        require(
            success,
            "StdCheats deployCodeTo(string,bytes,uint256,address): Failed to create runtime bytecode."
        );
        vm.etch(where, runtimeBytecode);
    }

    function run() public broadcast {
        // Deploy TaskManager

        deployCodeTo(
            "MockTaskManager.sol:TaskManager",
            abi.encode(msg.sender, 0, 1),
            TASK_MANAGER_ADDRESS
        );
        taskManager = TaskManager(TASK_MANAGER_ADDRESS);
        console.log("TaskManagerAdmin", taskManager.admin());

        // Deploy ACL

        // -> Deploy implementation
        ACL aclImplementation = new ACL();

        // -> Deploy proxy with implementation
        bytes memory initData = abi.encodeWithSelector(
            ACL.initialize.selector,
            msg.sender
        );
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(aclImplementation),
            initData
        );
        acl = ACL(address(proxy));

        // Set ACL in TaskManager

        taskManager.setACLContract(address(acl));

        console.log("TaskManager acl: ", address(taskManager.acl()));

        // Deploy zkVerifier

        deployCodeTo("MockZkVerifier.sol:MockZkVerifier", ZK_VERIFIER_ADDRESS);
        zkVerifier = MockZkVerifier(ZK_VERIFIER_ADDRESS);

        // Deploy QueryDecrypter

        deployCodeTo(
            "MockQueryDecrypter.sol:MockQueryDecrypter",
            QUERY_DECRYPTER_ADDRESS
        );
        queryDecrypter = MockQueryDecrypter(QUERY_DECRYPTER_ADDRESS);
    }
}
