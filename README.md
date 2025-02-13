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
npm install @fhenixprotocol/cofhe-foundry-mocks
```

## Usage

Import `FHEMocks.sol` and include it in your test file:

````solidity
import { CoFheTest } from "@fhenixprotocol/cofhe-foundry-mocks";

contract FHERC20Test is CoFheTest {
  ...
}
```

## Example

```solidity
pragma solidity ^0.8.20;

import {FHE, euint8, inEuint8} from "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract Example {

    euint8 _output;

    function setOutput(inEuint8 calldata _encryptedNumber) public  {
        _output = FHE.asEuint8(_encryptedNumber);
    }

    function getOutputEncrypted(bytes32 publicKey) public view returns (bytes memory) {
        return _output.seal(publicKey);
    }
}
```

## License

This project is licensed under MIT.
````
