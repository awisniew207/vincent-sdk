# Vincent SDK

A library for creating and verifying JWTs using PKP (Programmable Key Pairs) wallets with Ethereum signature compatibility. This SDK integrates with Lit Protocol to provide secure authentication capabilities using blockchain-based key pairs.

## Installation

```bash
npm install vincent-sdk
```

## Usage

### Creating a JWT with a PKP Wallet

```typescript
import { createPKPSignedJWT } from 'vincent-sdk';
import { PKPEthersWallet } from '@lit-protocol/pkp-ethers';

// Initialize your PKP wallet
const pkpWallet = new PKPEthersWallet({ /* your PKP wallet config */ });

// Your PKP information object
const pkpInfo = {
  publicKey: '0x...' // Your PKP public key
};

// Create a JWT with custom payload
const jwt = await createPKPSignedJWT(
  pkpWallet,
  pkpInfo,
  { name: "User Name", customClaim: "value" },
  30, // expires in 30 minutes
  "example.com" // audience claim - the domain this token is intended for
);

console.log(jwt);

// You can also specify multiple audience domains
const jwtWithMultipleAudiences = await createPKPSignedJWT(
  pkpWallet,
  pkpInfo,
  { name: "User Name", customClaim: "value" },
  30, // expires in 30 minutes
  ["api.example.com", "admin.example.com"] // multiple audience domains
);
```

### Verifying a JWT

#### Simple Verification

```typescript
import { verifyJWTSignature } from 'vincent-sdk';

// Verify a JWT - returns true only if signature is valid, token is not expired, 
// and time claims (iat, nbf) are valid
if (await verifyJWTSignature(jwt)) {
  console.log("JWT is valid!");
} else {
  console.log("JWT is invalid!");
}

// You can also verify the JWT with audience validation
if (await verifyJWTSignature(jwt, "example.com")) {
  console.log("JWT is valid and intended for example.com!");
} else {
  console.log("JWT is invalid or not intended for example.com!");
}
```

#### Detailed Verification

```typescript
import { verifyJWTSignatureDetailed } from 'vincent-sdk';

// Get detailed verification results
const { isVerified, isExpired, isValidTime, decodedPayload } = await verifyJWTSignatureDetailed(jwt);

console.log("Signature valid?", isVerified);
console.log("Token expired?", isExpired);
console.log("Time claims valid?", isValidTime);
console.log("Payload:", decodedPayload);

// Check audience if needed
const isIntendedForMyDomain = Array.isArray(decodedPayload.aud) 
  ? decodedPayload.aud.includes('myapp.com')
  : decodedPayload.aud === 'myapp.com';

// If all validations pass, token is valid
if (isVerified && !isExpired && isValidTime && isIntendedForMyDomain) {
  console.log("JWT verified successfully and intended for my domain!");
} else {
  console.log("JWT verification failed");
}
```

## Features

- Create JWT tokens signed by PKP wallets
- Verify JWT signatures against PKP public keys
- Support for audience (aud) claim with single or multiple domains
- Automatically includes standard JWT claims (exp, iat)
- Validates token expiration, issuance time (iat), and not-before time (nbf)
- Optional audience validation during verification
- Compatible with Ethereum's signing method
- Simple boolean verification and detailed verification options

## API Reference

### `createPKPSigner(pkpWallet: PKPEthersWallet)`

Creates a signer function that can be used with did-jwt to sign JWTs using a PKP wallet.

### `createPKPSignedJWT(pkpWallet, pkp, payload, expiresInMinutes = 10, audience?: string | string[])`

Creates a JWT signed by the provided PKP wallet with the specified payload.

Parameters:
- `pkpWallet`: PKP Ethers wallet instance
- `pkp`: Object containing PKP information (must include publicKey)
- `payload`: Custom claims to include in the JWT
- `expiresInMinutes`: Duration until the token expires (default: 10 minutes)
- `audience`: Optional domain or array of domains this token is intended for (aud claim)

### `verifyJWTSignature(jwt: string, expectedAudience?: string): Promise<boolean>`

Simple verification function that returns a boolean indicating if the JWT is valid.

Parameters:
- `jwt`: The JWT string to verify
- `expectedAudience`: Optional domain that should be in the audience claim

Returns:
- `boolean`: True if signature is valid, token is not expired, time claims are valid, and (if specified) the expected audience is included in the token's audience claim

### `verifyJWTSignatureDetailed(jwt: string, expectedAudience?: string)`

Detailed verification function that returns comprehensive validation results.

Parameters:
- `jwt`: The JWT string to verify
- `expectedAudience`: Optional domain that should be in the audience claim

Returns:
- `isVerified`: Boolean indicating if the signature is valid
- `isExpired`: Boolean indicating if the JWT has expired
- `isValidTime`: Boolean indicating if the JWT is valid in time (checks iat and nbf claims)
- `isValidAudience`: Boolean indicating if the expected audience is included in the token's audience claim (only if expectedAudience is provided)
- `decodedPayload`: The decoded payload from the JWT

### Utility functions

The SDK also includes several utility functions:

- `hexToUint8Array(hex: string)`: Converts a hex string to a Uint8Array
- `validateJWTTime(payload: any)`: Validates if a JWT is within its valid time window
- `isJWTExpired(payload: any)`: Checks if a JWT has expired
- `processJWTSignature(signatureBase64Url: string)`: Processes a JWT signature from base64url to binary
- `splitJWT(jwt: string)`: Splits a JWT into its component parts

## License

ISC

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 