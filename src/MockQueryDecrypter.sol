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

    constructor() {
        taskManager = TaskManager(TASK_MANAGER_ADDRESS);
        acl = ACL(taskManager.acl());
    }

    function queryDecrypt(
        Permission memory permission,
        uint256 ctHash
    ) public view returns (uint256) {
        acl.isAllowedWithPermission(permission, ctHash);
        return taskManager.mockStorage(ctHash);
    }
}
