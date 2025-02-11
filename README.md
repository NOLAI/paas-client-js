# PAAS client (JavaScript/TypeScript)
[![npm](https://img.shields.io/npm/v/@nolai/paas-client.svg)](https://www.npmjs.com/package/@nolai/paas-client)
[![Downloads](https://img.shields.io/npm/dm/@nolai/paas-client.svg)](https://www.npmjs.com/package/@nolai/paas-client)
[![License](https://img.shields.io/npm/l/@nolai/paas-client.svg)](https://github.com/NOLAI/paas-client-js/blob/main/LICENSE)

This project contains the JavaScript/TypeScript client implementation for PAAS, the PEP Authorisation API Service (or _Pseudonymization as a Service_).
It implements interaction with multiple [PAAS servers](https://github.com/NOLAI/paas-server) using the [PAAS API](https://github.com/NOLAI/paas-api).

PAAS forms a REST API around [`libpep`](https://github.com/NOLAI/libpep) for homomorphic pseudonymization.
Using multiple PAAS transcryptors, it is possible to blindly convert encrypted pseudonyms, encrypted by clients, into different encrypted pseudonyms for different clients, in a distributed manner.
As long as 1 transcryptor is not compromised, the pseudonymization is secure, meaning that nobody can link pseudonyms of different clients together.

Each transcryptor is able to enforce access control policies, such as only allowing pseudonymization for certain domains or contexts.
This way, using PAAS, you can enforce central monitoring and control over unlinkable data processing in different domains or contexts.

## Installation 
The JS/TS client is available [here](https://www.npmjs.com/package/@nolai/paas-client)

To install it, run:

```npm install @nolai/paas-client @nolai/libpep-wasm```

or

```yarn add @nolai/paas-client @nolai/libpep-wasm```

> [!CAUTION]
> Make sure to allways have the same `@nolai/libpep-wasm` version as `@nolai/paas-client`. Some bundlers could download the other version and paas-client would be not using the same wasm file that you use in other parts of your project


## Usage
We provide a simple example of how to use the client.

```typescript
import {EncryptionContexts} from "./sessions";

const config: PseudonymServiceConfig = {
    blindedGlobalPrivateKey: BlindedGlobalSecretKey.fromHex(
        "dacec694506fa1c1ab562059174b022151acab4594723614811eaaa93a9c5908",
    ),
    globalPublicKey: GlobalPublicKey.fromHex(
        "3025b1584bc729154f33071f73bb9499509bb504f887496ba86cb57e88d5dc62",
    ),
    transcryptors: [
        new TranscryptorConfig("test_system_1", "http://localhost:8080"),
        new TranscryptorConfig("test_system_2", "http://localhost:8081"),
    ],
};

const authTokens = new new Map(
    [["test_system_1", "test_token_1"], ["test_system_2", "test_token_2"],],
)

const encryptedPseudonym = EncryptedPseudonym.fromBase64(
    "nr3FRadpFFGCFksYgrloo5J2V9j7JJWcUeiNBna66y78lwMia2-l8He4FfJPoAjuHCpH-8B0EThBr8DS3glHJw==",
);

const sessions = new EncryptionContexts( 
    new Map(
        [
            ["test_system_1", "session_1"], 
            ["test_system_2", "session_2"],
        ],
));

const domainFrom = "domain1";
const domainTo = "domain2";

const service = new PseudonymService(config, authTokens);
const result = await service.pseudonymize(
    encryptedPseudonym,
    sessions,
    domainFrom,
    domainTo,
);
const pseudonym = await service.decryptPseudonym(result);
console.log(pseudonym.asHex()) 
```
