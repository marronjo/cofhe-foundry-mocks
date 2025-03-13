// SPDX-License-Identifier: BSD-3-Clause-Clear
// solhint-disable one-contract-per-file

pragma solidity >=0.8.19 <0.9.0;

import {Permission} from "./Permissioned.sol";
import {ACL} from "./ACL.sol";
import {TaskManager} from "./MockTaskManager.sol";
import {TASK_MANAGER_ADDRESS} from "./FHE.sol";

contract MockQueryDecrypter {
    TaskManager public taskManager;
    ACL public acl;

    error SealingKeyMissing();
    error SealingKeyInvalid();

    constructor() {
        taskManager = TaskManager(TASK_MANAGER_ADDRESS);
        acl = ACL(taskManager.acl());
    }

    // EXISTENCE

    function exists() public pure returns (bool) {
        return true;
    }

    // BODY

    function queryDecrypt(
        Permission memory permission,
        uint256 ctHash
    ) public view returns (uint256) {
        if (permission.sealingKey != bytes32(0)) revert SealingKeyInvalid();

        acl.isAllowedWithPermission(permission, ctHash);
        return taskManager.mockStorage(ctHash);
    }

    function seal(uint256 input, bytes32 key) public pure returns (bytes32) {
        return bytes32(input) ^ key;
    }

    function unseal(bytes32 hashed, bytes32 key) public pure returns (uint256) {
        return uint256(hashed ^ key);
    }

    function querySealOutput(
        Permission memory permission,
        uint256 ctHash
    ) public view returns (bytes32) {
        if (permission.sealingKey == bytes32(0)) revert SealingKeyMissing();

        acl.isAllowedWithPermission(permission, ctHash);
        uint256 value = taskManager.mockStorage(ctHash);
        return seal(value, permission.sealingKey);
    }
}
