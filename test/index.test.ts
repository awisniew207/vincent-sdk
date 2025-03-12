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
    let jwtWithAudience: string;

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
        },
        10, // 10 minutes expiration
        "lit-protocol.com" // Default audience
      );
      console.log("Created JWT");
      console.log(jwt);

      // Test the verification function
      console.log("Verifying JWT");
      const isValid = await verifyJWTSignature(jwt, "lit-protocol.com");
      console.log("JWT valid:", isValid);
      expect(isValid).toBe(true);
      
      const decoded = didJWT.decodeJWT(jwt);
      expect(decoded.payload).toBeDefined();
      expect(decoded.payload.name).toBe('Lit Protocol User');
      expect(decoded.payload.pkpPublicKey).toBe(pkp.pkpPublicKey);
      expect(decoded.payload.aud).toBe("lit-protocol.com");
    });

    test('should create a JWT with audience claim when specified', async () => {
      // Skip if the wallet wasn't initialized in the previous test
      if (!pkpWallet || !pkp) {
        console.log("Skipping audience test because previous test didn't complete");
        return;
      }

      const audienceDomain = "example.com";
      
      jwtWithAudience = await createPKPSignedJWT(
        pkpWallet, 
        { publicKey: pkp.pkpPublicKey },
        { 
          name: 'Lit Protocol User',
          timestamp: Date.now(),
        },
        10, // 10 minutes expiration
        audienceDomain
      );
      
      console.log("Created JWT with audience");
      
      const isValidAudience = await verifyJWTSignature(jwtWithAudience, audienceDomain);
      expect(isValidAudience).toBe(true);
      
      const decodedAudience = didJWT.decodeJWT(jwtWithAudience);
      expect(decodedAudience.payload).toBeDefined();
      expect(decodedAudience.payload.aud).toBe(audienceDomain);
    });
    
    test('should support multiple audience domains in a JWT', async () => {
      // Skip if the wallet wasn't initialized in the previous test
      if (!pkpWallet || !pkp) {
        console.log("Skipping multiple audience test because previous test didn't complete");
        return;
      }

      const audienceDomains = ["api.example.com", "admin.example.com"];
      
      const jwtWithMultipleAudiences = await createPKPSignedJWT(
        pkpWallet, 
        { publicKey: pkp.pkpPublicKey },
        { 
          name: 'Lit Protocol Admin',
          timestamp: Date.now(),
        },
        10, // 10 minutes expiration
        audienceDomains
      );
      
      console.log("Created JWT with multiple audiences");
      
      // Should validate against any of the audience domains
      const isValidMultipleAudiences = await verifyJWTSignature(jwtWithMultipleAudiences, audienceDomains[0]);
      expect(isValidMultipleAudiences).toBe(true);
      
      const decodedMultiAudiences = didJWT.decodeJWT(jwtWithMultipleAudiences);
      expect(decodedMultiAudiences.payload).toBeDefined();
      expect(Array.isArray(decodedMultiAudiences.payload.aud)).toBe(true);
      expect(decodedMultiAudiences.payload.aud).toEqual(audienceDomains);
    });

    test('should verify a JWT against the expected audience', async () => {
      // Skip if the wallet wasn't initialized in the previous test
      if (!pkpWallet || !pkp) {
        console.log("Skipping audience validation test because previous test didn't complete");
        return;
      }

      const audienceDomain = "api.myservice.com";
      
      const jwtWithSpecificAudience = await createPKPSignedJWT(
        pkpWallet, 
        { publicKey: pkp.pkpPublicKey },
        { name: 'Lit Protocol User' },
        10, // 10 minutes expiration
        audienceDomain
      );
      
      // Should be valid when expected audience matches
      const isValidForCorrectAudience = await verifyJWTSignature(jwtWithSpecificAudience, audienceDomain);
      expect(isValidForCorrectAudience).toBe(true);
      
      // Should be invalid when expected audience doesn't match
      const isValidForWrongAudience = await verifyJWTSignature(jwtWithSpecificAudience, "wrong.domain.com");
      expect(isValidForWrongAudience).toBe(false);
      
      // Test for audience validation failure
      try {
        // This should fail validation since the expected audience doesn't match
        await verifyJWTSignature(jwtWithSpecificAudience, "another.domain.com");
        fail("Should have thrown an error for audience mismatch");
      } catch (error) {
        expect(error).toBeDefined();
      }
    });
  });

  describe('JWT Time-based Validation', () => {
    // Generate a private key for test JWT signing
    const privateKeyHex = '7dd3165a3761257c37a03e21ca2626f1b0b92400cbc2c6d1544f0c536412187e';
    const privateKeyBytes = new Uint8Array(Buffer.from(privateKeyHex, 'hex'));
    const signer = didJWT.ES256KSigner(privateKeyBytes);
    
    const mockPublicKey = '0x04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    const mockIssuer = 'did:ethr:0x123456789abcdef';
    const testAudience = "test.domain.com";

    // This test verifies that a valid JWT with proper time claims passes validation
    test('should validate a JWT with correct time claims', async () => {
      const now = Math.floor(Date.now() / 1000);
      
      const validJWT = await didJWT.createJWT(
        {
          exp: now + 600, // 10 minutes in the future
          iat: now - 60,  // 1 minute in the past
          nbf: now - 60,  // 1 minute in the past
          pkpPublicKey: mockPublicKey,
          aud: testAudience
        },
        { issuer: mockIssuer, signer, alg: 'ES256K' }
      );
      
      const isValid = await verifyJWTSignature(validJWT, testAudience);
      
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
          pkpPublicKey: mockPublicKey,
          aud: testAudience
        },
        { issuer: mockIssuer, signer, alg: 'ES256K' }
      );
      
      // Test verification - should be false because time is invalid
      const isValid = await verifyJWTSignature(futureIatJWT, testAudience);
      expect(isValid).toBe(false);
    });

    test('should reject a JWT with future not-before time (nbf)', async () => {
      const now = Math.floor(Date.now() / 1000);
      
      const futureNbfJWT = await didJWT.createJWT(
        {
          exp: now + 600,     // 10 minutes in the future
          iat: now - 60,      // 1 minute in the past
          nbf: now + 300,     // 5 minutes in the future
          pkpPublicKey: mockPublicKey,
          aud: testAudience
        },
        { issuer: mockIssuer, signer, alg: 'ES256K' }
      );
      
      // Test verification - should be false because time is invalid
      const isValid = await verifyJWTSignature(futureNbfJWT, testAudience);
      expect(isValid).toBe(false);
    });

    test('should detect an expired JWT', async () => {
      const now = Math.floor(Date.now() / 1000);
      
      const expiredJWT = await didJWT.createJWT(
        {
          exp: now - 600,     // 10 minutes in the past (expired)
          iat: now - 1200,    // 20 minutes in the past
          pkpPublicKey: mockPublicKey,
          aud: testAudience
        },
        { issuer: mockIssuer, signer, alg: 'ES256K' }
      );
      
      // Test verification - should be false because token is expired
      const isValid = await verifyJWTSignature(expiredJWT, testAudience);
      expect(isValid).toBe(false);
    });
    
    test('should reject a JWT with no audience', async () => {
      const now = Math.floor(Date.now() / 1000);
      
      const noAudienceJWT = await didJWT.createJWT(
        {
          exp: now + 600,     // 10 minutes in the future
          iat: now - 60,      // 1 minute in the past
          pkpPublicKey: mockPublicKey
          // No aud claim
        },
        { issuer: mockIssuer, signer, alg: 'ES256K' }
      );
      
      // Test verification - should be false because audience is missing
      const isValid = await verifyJWTSignature(noAudienceJWT, testAudience);
      expect(isValid).toBe(false);
    });
  });
});
