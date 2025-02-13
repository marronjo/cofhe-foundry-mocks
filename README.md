# cofhe-foundry-mocks [![NPM Package][npm-badge]][npm] [![License: MIT][license-badge]][license]

[npm]: https://www.npmjs.com/package/@fhenixprotocol/cofhe-foundry-mocks
[npm-badge]: https://img.shields.io/npm/v/@fhenixprotocol/cofhe-foundry-mocks.svg
[license]: https://opensource.org/licenses/MIT
[license-badge]: https://img.shields.io/badge/License-MIT-blue.svg

Utility contracts for locally testing FHE locally in foundry.

Need help getting started? Check out the [fhenix documentation](https://docs.fhenix.io)!

These contracts are still under heavy constructions and will be changing frequently. Consider binding your contracts to a specific version, and keep an eye on the [changelog](https://github.com/FhenixProtocol/cofhe-contracts/CHANGELOG.md)

## Install

```
forge install fhenixprotocol/cofhe-foundry-mocks
```

add the following remapping:

```
@fhenixprotocol/cofhe-foundry-mocks/=lib/cofhe-foundry-mocks/src/
```

## Usage

Import `CoFheTest` from `@fhenix-protocol/cofhe-foundry-mocks/CoFheTest.sol` and include it in your test file:

```solidity

import {Test} from "forge-std/Test.sol";
import { CoFheTest } from "@fhenixprotocol/cofhe-foundry-mocks/CoFheTest.sol";

contract FHERC20Test is Test {
    CoFheTest CFT;

    ...

    function setUp() public {
        CFT = new CoFheTest();
        ...
}
```

Creating a new `CoFheTest` contract initializes a mock CoFHE `TaskManager` which stores encrypted values locally as cleartext. This mock TM contract is etched to the address found in `FHE.sol`, and will handle all `FHE.___` calls.

:::
`FHE.sealoutput` and `FHE.decrypt` return the result asynchronously to contracts implementing `IAsyncFHEReceiver`. Due to the nature of foundry tests, these async callbacks are called synchronously.
:::

Additionally, you now have access to `CFT` which has the following functions (the following examples and more can be found in `ExampleFHECounter.t.sol`)

### `CFT.createInE_____` utility

Used to create `inEBool` / `inEuintXX` / `inAddress` to be used as function inputs.

```solidity
// Set number to 5
inEuint32 memory inNumber = CFT.createInEuint32(5);
counter.setNumber(inNumber);
```

### `CFT.assertStoredValue` assertion

- Param 1: An encrypted value (ebool / euint8 ... euint256 / eaddress) or the hash of a value (inEuint32.hash / ebool.unwrap(eBoolVal))
- Param 2: The expected encrypted value

This will revert if the encrypted hash isn't stored, or if the expected value doesn't match.

```solidity
function test_setNumber() public {
    inEuint32 memory inNumber = CFT.createInEuint32(10);
    counter.setNumber(inNumber);
    CFT.assertStoredValue(counter.eNumber(), 10);
}
```

### `CFT.unseal` utility

Instead of doing a true asymmetric encryption, the mock `TaskManager` uses a simple XOR to seal an output. The `CFT.unseal` function uses the publicKey used to seal a value, and returns the unsealed result.

```solidity
function test_sealoutput() public {
    bytes32 publicKey = bytes32("0xFakePublicKey");

    counter.sealoutput(publicKey);

    uint256 unsealed = CFT.unseal(
        counter.sealedRes(euint32.unwrap(counter.eNumber())),
        publicKey
    );

    assertEq(unsealed, 5);
}
```

## License

This project is licensed under MIT.
