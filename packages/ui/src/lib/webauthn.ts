// WebAuthn's JSON forms, both ways: the options coffre answers, as `create()` and `get()` take them, and the
// credential they give, as the verifier reads it (`toJSON()`), written out for the browsers that lack
// `parseRequestOptionsFromJSON` and its kin.

import { withinDeadline } from './passkey-answer.ts';

export type Descriptor = { type: 'public-key'; id: string; transports?: string[] };
export type RequestJSON = { challenge: string; rpId: string; allowCredentials: Descriptor[]; userVerification: UserVerificationRequirement; timeout: number };
export type CreationJSON = {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  authenticatorSelection: AuthenticatorSelectionCriteria;
  attestation: AttestationConveyancePreference;
  excludeCredentials: Descriptor[];
  timeout: number;
};

const bytes = (value: string): ArrayBuffer => {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out.buffer;
};

const text = (buffer: ArrayBuffer | null): string | null => {
  if (buffer === null) return null;
  let binary = '';
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const descriptors = (list: Descriptor[]): PublicKeyCredentialDescriptor[] =>
  list.map(({ type, id, transports }) => ({ type, id: bytes(id), ...(transports === undefined ? {} : { transports: transports as AuthenticatorTransport[] }) }));

/** WebAuthn's JSON form as `get()` takes it: `parseRequestOptionsFromJSON`, written out for the browsers that lack it. */
export function requestOptions(options: RequestJSON): PublicKeyCredentialRequestOptions {
  return { ...options, challenge: bytes(options.challenge), allowCredentials: descriptors(options.allowCredentials) };
}

/** And as `create()` takes it. */
export function creationOptions(options: CreationJSON): PublicKeyCredentialCreationOptions {
  return {
    ...options,
    challenge: bytes(options.challenge),
    user: { ...options.user, id: bytes(options.user.id) },
    excludeCredentials: descriptors(options.excludeCredentials),
  };
}

/** The credential as `toJSON()` gives it, written out for the browsers that lack it: what the verifier reads. */
export function toJSON(credential: PublicKeyCredential): unknown {
  const response = credential.response;
  const common = {
    id: credential.id,
    rawId: text(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  if ('attestationObject' in response) {
    const attestation = response as AuthenticatorAttestationResponse;
    return {
      ...common,
      response: { clientDataJSON: text(attestation.clientDataJSON), attestationObject: text(attestation.attestationObject), transports: attestation.getTransports?.() ?? [] },
    };
  }
  const assertion = response as AuthenticatorAssertionResponse;
  return {
    ...common,
    response: {
      clientDataJSON: text(assertion.clientDataJSON),
      authenticatorData: text(assertion.authenticatorData),
      signature: text(assertion.signature),
      userHandle: text(assertion.userHandle),
    },
  };
}

/**
 * `create()` with these options, ended at their `timeout` (`withinDeadline`), not only asked to end then: the timeout
 * is the step's time left, and a browser stretches a short one. Throws as `create()` does, `NotAllowedError` for no
 * answer, and `TimeoutError` once the page ended it.
 */
export async function createCredential(options: CreationJSON, closed?: AbortSignal): Promise<PublicKeyCredential> {
  const credential = await withinDeadline(options.timeout, (signal) => navigator.credentials.create({ publicKey: creationOptions(options), signal }), closed);
  if (credential === null) throw new DOMException('no passkey answered', 'NotAllowedError');
  return credential as PublicKeyCredential;
}

/** `get()` with these options, ended at their `timeout`, as `createCredential`. */
export async function getCredential(options: RequestJSON): Promise<PublicKeyCredential> {
  const credential = await withinDeadline(options.timeout, (signal) => navigator.credentials.get({ publicKey: requestOptions(options), signal }));
  if (credential === null) throw new DOMException('no passkey answered', 'NotAllowedError');
  return credential as PublicKeyCredential;
}
