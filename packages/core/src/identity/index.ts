// `@coffre/core/identity`: who is asking, and how coffre's sign-in finds out.
export * from './auth.ts';
export * from './constraints.ts';
export * from './dpop.ts';
export * from './github-app.ts';
export * from './profile-rules.ts';
export * from './run-proof.ts';
export * from './signin/index.ts';
export * from './tokens.ts';
export * from './types.ts';
export * from './verifier.ts';
// Passkeys' verifier; its CBOR reader stays the module's own.
export {
  PASSKEY_ALGORITHMS,
  base64urlLength,
  MAX_CREDENTIAL_ID,
  verifyAssertion,
  verifyRegistration,
  type AssertionExpectation,
  type CeremonyExpectation,
  type PasskeyAlgorithm,
  type PasskeyFlags,
  type PasskeyReason,
  type PasskeyRefusal,
  type RegistrationExpectation,
  type StoredPasskey,
  type VerifiedAssertion,
  type VerifiedRegistration,
  USER_VERIFICATION,
} from './webauthn.ts';
export * from './workloads.ts';
export * from './workload-token.ts';
