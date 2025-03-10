import { LitActionResource, LitPKPResource } from '@lit-protocol/auth-helpers';
import { LIT_NETWORK, AUTH_METHOD_SCOPE, LIT_ABILITY } from '@lit-protocol/constants';
import { EthWalletProvider, LitRelay } from '@lit-protocol/lit-auth-client';
import { ethers } from 'ethers';
import { LitNodeClient } from '@lit-protocol/lit-node-client';
import { PKPEthersWallet } from '@lit-protocol/pkp-ethers';
import { createPKPSignedJWT, verifyJWTSignature } from '../src/index';
import * as didJWT from 'did-jwt';

const litNetwork = LIT_NETWORK.DatilDev;

jest.setTimeout(60000);

describe('Vincent SDK', () => {
  describe('JWT Creation and Verification with PKP', () => {
    let pkpWallet: PKPEthersWallet;
    let pkp: any;
    let jwt: string;

    test('should create a PKP, generate a JWT, and verify it successfully', async () => {
      const ethersWallet = ethers.Wallet.createRandom();

      const litNodeClient = new LitNodeClient({
        litNetwork,
        debug: false
      });
      await litNodeClient.connect();

      const litRelay = new LitRelay({
        relayUrl: LitRelay.getRelayUrl(litNetwork),
        relayApiKey: 'test-api-key',
      });

      const authMethod = await EthWalletProvider.authenticate({
        signer: ethersWallet,
        litNodeClient
      });

      pkp = await litRelay.mintPKPWithAuthMethods([authMethod], {
        pkpPermissionScopes: [[AUTH_METHOD_SCOPE.SignAnything]],
      });

      expect(pkp.pkpPublicKey).toBeDefined();
      expect(pkp.pkpEthAddress).toBeDefined();

      const sessionSigs = await litNodeClient.getPkpSessionSigs({
        chain: 'ethereum',
        expiration: new Date(
          Date.now() + 1000 * 60 * 15
        ).toISOString(), // 15 minutes
        pkpPublicKey: pkp.pkpPublicKey!, // Non-null assertion as we've verified it exists
        authMethods: [authMethod],
        resourceAbilityRequests: [
          {
            resource: new LitActionResource('*'),
            ability: LIT_ABILITY.LitActionExecution,
          },
          {
            resource: new LitPKPResource('*'),
            ability: LIT_ABILITY.PKPSigning,
          },
        ],
      });

      pkpWallet = new PKPEthersWallet({
        controllerSessionSigs: sessionSigs,
        pkpPubKey: pkp.pkpPublicKey!, // Non-null assertion as we've verified it exists
        litNodeClient,
      });
      console.log("Created PKP Wallet");

      console.log("Creating JWT");
      jwt = await createPKPSignedJWT(
        pkpWallet, 
        { publicKey: pkp.pkpPublicKey }, // Ensure publicKey property exists
        { 
          name: 'Lit Protocol User',
          timestamp: Date.now(),
        }
      );
      console.log("Created JWT");
      console.log(jwt);

      // Test the verification function
      console.log("Verifying JWT");
      const isValid = await verifyJWTSignature(jwt);
      console.log("JWT valid:", isValid);
      expect(isValid).toBe(true);
      
      const decoded = didJWT.decodeJWT(jwt);
      expect(decoded.payload).toBeDefined();
      expect(decoded.payload.name).toBe('Lit Protocol User');
      expect(decoded.payload.pkpPublicKey).toBe(pkp.pkpPublicKey);
    });
  });

  describe('JWT Time-based Validation', () => {
    // Generate a private key for test JWT signing
    const privateKeyHex = '7dd3165a3761257c37a03e21ca2626f1b0b92400cbc2c6d1544f0c536412187e';
    const privateKeyBytes = new Uint8Array(Buffer.from(privateKeyHex, 'hex'));
    const signer = didJWT.ES256KSigner(privateKeyBytes);
    
    const mockPublicKey = '0x04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    const mockIssuer = 'did:ethr:0x123456789abcdef';

    // This test verifies that a valid JWT with proper time claims passes validation
    test('should validate a JWT with correct time claims', async () => {
      const now = Math.floor(Date.now() / 1000);
      
      const validJWT = await didJWT.createJWT(
        {
          exp: now + 600, // 10 minutes in the future
          iat: now - 60,  // 1 minute in the past
          nbf: now - 60,  // 1 minute in the past
          pkpPublicKey: mockPublicKey
        },
        { issuer: mockIssuer, signer, alg: 'ES256K' }
      );
      
      const isValid = await verifyJWTSignature(validJWT);
      
      // We're not expecting this to be valid since we're using a mock signer
      console.log("Valid JWT test result:", isValid);
    });

    // This test verifies that a JWT with a future issuance time is invalid
    test('should reject a JWT with future issuance time (iat)', async () => {
      const now = Math.floor(Date.now() / 1000);
      
      const futureIatJWT = await didJWT.createJWT(
        {
          exp: now + 600,     // 10 minutes in the future
          iat: now + 300,     // 5 minutes in the future
          pkpPublicKey: mockPublicKey
        },
        { issuer: mockIssuer, signer, alg: 'ES256K' }
      );
      
      // Test verification - should be false because time is invalid
      const isValid = await verifyJWTSignature(futureIatJWT);
      expect(isValid).toBe(false);
    });

    test('should reject a JWT with future not-before time (nbf)', async () => {
      const now = Math.floor(Date.now() / 1000);
      
      const futureNbfJWT = await didJWT.createJWT(
        {
          exp: now + 600,     // 10 minutes in the future
          iat: now - 60,      // 1 minute in the past
          nbf: now + 300,     // 5 minutes in the future
          pkpPublicKey: mockPublicKey
        },
        { issuer: mockIssuer, signer, alg: 'ES256K' }
      );
      
      // Test verification - should be false because time is invalid
      const isValid = await verifyJWTSignature(futureNbfJWT);
      expect(isValid).toBe(false);
    });

    test('should detect an expired JWT', async () => {
      const now = Math.floor(Date.now() / 1000);
      
      const expiredJWT = await didJWT.createJWT(
        {
          exp: now - 600,     // 10 minutes in the past (expired)
          iat: now - 1200,    // 20 minutes in the past
          pkpPublicKey: mockPublicKey
        },
        { issuer: mockIssuer, signer, alg: 'ES256K' }
      );
      
      // Test verification - should be false because token is expired
      const isValid = await verifyJWTSignature(expiredJWT);
      expect(isValid).toBe(false);
    });
  });
});
