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
  30 // expires in 30 minutes
);

console.log(jwt);
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

// If all validations pass, token is valid
if (isVerified && !isExpired && isValidTime) {
  console.log("JWT verified successfully!");
} else {
  console.log("JWT verification failed");
}
```

## Features

- Create JWT tokens signed by PKP wallets
- Verify JWT signatures against PKP public keys
- Automatically includes standard JWT claims (exp, iat)
- Validates token expiration, issuance time (iat), and not-before time (nbf)
- Compatible with Ethereum's signing method
- Simple boolean verification and detailed verification options

## API Reference

### `createPKPSigner(pkpWallet: PKPEthersWallet)`

Creates a signer function that can be used with did-jwt to sign JWTs using a PKP wallet.

### `createPKPSignedJWT(pkpWallet, pkp, payload, expiresInMinutes = 10)`

Creates a JWT signed by the provided PKP wallet with the specified payload.

Parameters:
- `pkpWallet`: PKP Ethers wallet instance
- `pkp`: Object containing PKP information (must include publicKey)
- `payload`: Custom claims to include in the JWT
- `expiresInMinutes`: Duration until the token expires (default: 10 minutes)

### `verifyJWTSignature(jwt: string): Promise<boolean>`

Simple verification function that returns a boolean indicating if the JWT is valid.

Returns:
- `boolean`: True if signature is valid, token is not expired, and time claims are valid

### `verifyJWTSignatureDetailed(jwt: string)`

Detailed verification function that returns comprehensive validation results.

Returns:
- `isVerified`: Boolean indicating if the signature is valid
- `isExpired`: Boolean indicating if the JWT has expired
- `isValidTime`: Boolean indicating if the JWT is valid in time (checks iat and nbf claims)
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