import * as didJWT from 'did-jwt';
import * as secp256k1 from '@noble/secp256k1';
import { PKPEthersWallet } from '@lit-protocol/pkp-ethers';
import { ethers } from 'ethers';
import { Buffer } from 'buffer';
import { 
  isJWTExpired, 
  validateJWTTime, 
  splitJWT, 
  processJWTSignature 
} from './utils';

/**
 * Creates a signer function compatible with did-jwt that uses a PKP wallet for signing
 * 
 * This function returns a signing function that conforms to the did-jwt library's
 * signer interface. When called, it signs data using the PKP wallet, formatting
 * the signature according to ES256K requirements (without recovery parameter).
 * 
 * @param pkpWallet - The PKP Ethers wallet instance that will be used for signing
 * @returns A signing function that takes data and returns a base64url-encoded signature
 * @example
 * ```typescript
 * const pkpWallet = new PKPEthersWallet({ ... });
 * const signer = createPKPSigner(pkpWallet);
 * const signature = await signer('data to sign');
 * ```
 */
export function createPKPSigner(pkpWallet: PKPEthersWallet) {
  /**
   * Converts a hex string to a Uint8Array
   * 
   * @param hex - The hex string to convert (with or without 0x prefix)
   * @returns A Uint8Array representation of the hex string
   */
  const hexToUint8Array = (hex: string): Uint8Array => {
    if (hex.startsWith('0x')) {
      hex = hex.slice(2);
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
  };

  /**
   * The actual signer function conforming to the did-jwt signer interface
   * 
   * @param data - The data to sign, either as a string or Uint8Array
   * @returns A promise that resolves to the base64url-encoded signature
   */
  return async (data: string | Uint8Array): Promise<string> => {
    const dataBytes = typeof data === 'string' 
      ? Uint8Array.from(Buffer.from(data, 'utf8'))
      : data;
    
    const sig = await pkpWallet.signMessage(dataBytes);
    const { r, s } = ethers.utils.splitSignature(sig);

    const rBytes = hexToUint8Array(r.slice(2));
    const sBytes = hexToUint8Array(s.slice(2));
    
    // ES256K signature is r and s concatenated (64 bytes total)
    const sigBytes = new Uint8Array(64);
    sigBytes.set(rBytes, 0);
    sigBytes.set(sBytes, 32);
    
    // Convert to base64url encoding
    const base64Sig = Buffer.from(sigBytes).toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    
    return base64Sig;
  };
}

/**
 * Creates a JWT signed by a PKP wallet using the ES256K algorithm
 * 
 * This function creates a JWT with the provided payload, adding standard claims
 * like iat (issued at), exp (expiration), and iss (issuer). It also includes the
 * PKP public key in the payload, which is used for verification.
 * 
 * @param pkpWallet - The PKP Ethers wallet instance used for signing
 * @param pkp - The PKP information object containing controller information
 * @param payload - The custom payload to include in the JWT
 * @param expiresInMinutes - How long until the JWT expires (defaults to 10 minutes)
 * @param audience - The domain(s) this token is intended for (aud claim)
 * @returns A promise that resolves to the signed JWT string
 * @example
 * ```typescript
 * const jwt = await createPKPSignedJWT(
 *   pkpWallet,
 *   pkpInfo,
 *   { name: "Lit Protocol User", customField: "value" },
 *   30, // expires in 30 minutes
 *   "example.com" // audience domain
 * );
 * ```
 */
export async function createPKPSignedJWT(
  pkpWallet: PKPEthersWallet,
  pkp: any,
  payload: Record<string, any>,
  expiresInMinutes: number = 10,  // Default 10-minute expiration
  audience: string | string[]    // Optional audience domain(s)
): Promise<string> {
  const signer = createPKPSigner(pkpWallet);
  
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + expiresInMinutes * 60;
  
  const walletAddress = await pkpWallet.getAddress();
  
  const fullPayload: {
    iat: number;
    exp: number;
    timestamp: number;
    iss: string;
    pkpPublicKey: any;
    aud?: string | string[];
    [key: string]: any;
  } = {
    ...payload,
    iat,
    exp,
    timestamp: Date.now(),
    iss: `did:ethr:${walletAddress}`,
    pkpPublicKey: pkp.publicKey
  };

  // Add audience claim if provided
  if (audience) {
    fullPayload.aud = audience;
  }
  
  const jwt = await didJWT.createJWT(
    fullPayload,
    { issuer: `did:ethr:${walletAddress}`, signer, alg: 'ES256K' }
  );
  
  return jwt;
}

/**
 * Verifies a JWT signature
 * 
 * This function returns true only if:
 * 1. The JWT signature is valid
 * 2. The JWT is not expired
 * 3. All time claims (nbf, iat) are valid
 * 4. If an expected audience is provided, the JWT's audience claim includes it
 * 
 * @param jwt - The JWT string to verify
 * @param expectedAudience - Domain that should be in the audience claim
 * @returns boolean indicating if the JWT is completely valid
 * @example
 * ```typescript
 * if (await verifyJWTSignature(jwt, 'myapp.com')) {
 *   // JWT is valid and intended for myapp.com - process the request
 * } else {
 *   // JWT is invalid - reject the request
 * }
 * ```
 */
export async function verifyJWTSignature(jwt: string, expectedAudience: string): Promise<boolean> {
  try {
    const decoded = didJWT.decodeJWT(jwt);
    
    if (!decoded.payload.exp) {
      console.error('JWT verification failed: No expiration claim (exp) set');
      return false;
    }
    
    if (!decoded.payload.pkpPublicKey) {
      console.error('JWT verification failed: Missing pkpPublicKey in payload');
      return false;
    }
    
    const isExpired = isJWTExpired(decoded.payload);
    if (isExpired) {
      console.error('JWT verification failed: Token has expired');
      return false;
    }
    
    const isValidTime = validateJWTTime(decoded.payload);
    if (!isValidTime) {
      // Check which specific time claim is invalid
      const currentTime = Math.floor(Date.now() / 1000);
      if (decoded.payload.nbf && currentTime < decoded.payload.nbf) {
        console.error('JWT verification failed: Token not yet valid (nbf claim is in the future)');
      } else if (decoded.payload.iat && currentTime < decoded.payload.iat - 30) {
        console.error('JWT verification failed: Token issued in the future (iat claim is ahead of current time)');
      } else {
        console.error('JWT verification failed: Invalid time claims');
      }
      return false;
    }
    
    // Validate audience if expected audience is provided
    if (expectedAudience && decoded.payload.aud) {
      const audiences = Array.isArray(decoded.payload.aud) 
        ? decoded.payload.aud 
        : [decoded.payload.aud];
      
      if (!audiences.includes(expectedAudience)) {
        console.error(`JWT verification failed: Token not intended for ${expectedAudience}`);
        return false;
      }
    }
    
    try {
      const { signedData, signature } = splitJWT(jwt);
      
      // Process signature from base64url to binary
      const signatureBytes = processJWTSignature(signature);
      
      // Extract r and s values from the signature
      const r = signatureBytes.slice(0, 32);
      const s = signatureBytes.slice(32, 64);
      
      // Process public key
      let publicKey = decoded.payload.pkpPublicKey;
      if (publicKey.startsWith('0x')) {
        publicKey = publicKey.substring(2);
      }
      
      const publicKeyBytes = Buffer.from(publicKey, 'hex');
      
      // PKPEthersWallet.signMessage() adds Ethereum prefix, so we need to add it here too
      const ethPrefixedMessage = '\x19Ethereum Signed Message:\n' + signedData.length + signedData;
      const messageBuffer = Buffer.from(ethPrefixedMessage, 'utf8');
      
      const messageHash = ethers.utils.keccak256(messageBuffer);
      const messageHashBytes = Buffer.from(messageHash.substring(2), 'hex');
      
      const signatureForSecp = new Uint8Array([...r, ...s]);
      
      // Verify the signature against the public key
      const isVerified = secp256k1.verify(
        signatureForSecp, 
        messageHashBytes, 
        publicKeyBytes
      );
      
      if (!isVerified) {
        console.error('JWT verification failed: Invalid signature');
        return false;
      }
      
      return true;
    } catch (error) {
      console.error('JWT signature verification error:', error);
      return false;
    }
  } catch (error) {
    console.error('JWT verification error:', error);
    return false;
  }
}

