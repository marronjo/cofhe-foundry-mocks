# cofhe-foundry-mocks [![NPM Package][npm-badge]][npm] [![License: MIT][license-badge]][license]

[npm]: https://www.npmjs.com/package/@fhenixprotocol/cofhe-foundry-mocks
[npm-badge]: https://img.shields.io/npm/v/@fhenixprotocol/cofhe-foundry-mocks.svg
[license]: https://opensource.org/licenses/MIT
[license-badge]: https://img.shields.io/badge/License-MIT-blue.svg

Utility contracts for locally testing FHE locally in foundry.

Need help getting started? Check out the [fhenix documentation](https://docs.fhenix.io)!

These contracts are still under heavy constructions and will be changing frequently. Consider binding your contracts to a specific version, and keep an eye on the [changelog](https://github.com/FhenixProtocol/cofhe-contracts/CHANGELOG.md)

## Migration

v0.1.3 - Rename `assertStoredValue` to `assertHashValue`

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

contract ExampleFHECounterTest is Test {
    CoFheTest CFT;
    ...

    function setUp() public {
        CFT = new CoFheTest(false);
        ...
}
```

Creating a new `CoFheTest` contract initializes a mock CoFHE `TaskManager` which stores encrypted values locally as cleartext. This mock TM contract is etched to the address found in `FHE.sol`, and will handle all `FHE.___` calls. The boolean param is `log` which sets whether the mocked ops should be logged to the console.

> [!NOTE]  
> Outside of a test environment `FHE.sealoutput` and `FHE.decrypt` will resolve asynchronously. See `IAsyncFHEReceiver`. Due to the nature of foundry tests, these async callbacks are called synchronously.

Additionally, you now have access to `CFT` which has the following functions (the following examples and more can be found in `ExampleFHECounter.t.sol`)

### `CFT.createInE_____` utility

Used to create `inEBool` / `InEuintXX` / `inAddress` to be used as function inputs.

```solidity
// Set number to 5
InEuint32 memory inNumber = CFT.createInEuint32(5);
counter.setNumber(inNumber);
```

### `CFT.assertStoredValue` assertion

- Param 1: An encrypted value (ebool / euint8 ... euint256 / eaddress) or the hash of a value (InEuint32.hash / ebool.unwrap(eBoolVal))
- Param 2: The expected encrypted value

This will revert if the encrypted hash isn't stored, or if the expected value doesn't match.

```solidity
function test_setNumber() public {
    InEuint32 memory inNumber = CFT.createInEuint32(10);
    counter.setNumber(inNumber);
    CFT.assertStoredValue(counter.eNumber(), 10);
}
```

## License

This project is licensed under MIT.
