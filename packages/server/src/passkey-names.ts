// What a new passkey is called (docs/design/passkeys.md, section 3.6): its provider's name, where its AAGUID is one a
// passkey provider publishes, else "Passkey <n>". A name grants nothing and sits outside every MAC, so a wrong or
// missing one costs a rename, and the list names only the providers people use most. The AAGUIDs are those the
// passkeydeveloper/passkey-authenticator-aaguids list gave on 2026-11-06 (commit d53c0f35); security keys publish
// theirs in FIDO's metadata service, which coffre does not read, and stay "Passkey <n>".

const PROVIDERS: Readonly<Record<string, string>> = {
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'Apple Passwords',
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain (Managed)',
  'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac',
  '531126d6-e717-415c-9320-3d9aa6981239': 'Dashlane',
  '771b48fd-d3d4-4f74-9232-fc157ab0507a': 'Edge on Mac',
  'f3809540-7f14-49c1-a8b3-8f813b225541': 'Enpass',
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
  'fdb141b2-5d84-443e-8a35-4698c205a502': 'KeePassXC',
  '0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6': 'Keeper',
  'b78a0a55-6ef8-d246-a042-ba0f6d55050c': 'LastPass',
  'd3452668-01fd-4c12-926c-83a4204853aa': 'Microsoft Password Manager',
  'b84e4048-15dc-4dd0-8640-f4f60813c8af': 'NordPass',
  '50726f74-6f6e-5061-7373-50726f746f6e': 'Proton Pass',
  '53414d53-554e-4700-0000-000000000000': 'Samsung Pass',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
};

/** The AAGUID's provider name, if the list has it; null for none (an all-zero AAGUID, a security key, an unknown one). */
export function providerName(aaguid: Uint8Array | null): string | null {
  if (aaguid === null || aaguid.length !== 16) return null;
  const hex = Buffer.from(aaguid).toString('hex');
  return PROVIDERS[`${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`] ?? null;
}

/** A new passkey's name: its provider's, else "Passkey <n>", `n` one more than every passkey row the person has had. */
export function passkeyName(aaguid: Uint8Array | null, passkeysEver: number): string {
  return providerName(aaguid) ?? `Passkey ${passkeysEver + 1}`;
}
