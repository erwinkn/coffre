export type { KekProvider, WrappedDek, KeyOperation } from './types.ts';
export { DEK_BYTES, KekUnavailableError, KekCancelledError, KekBadClaimError } from './types.ts';
export { LocalKekProvider, equalBytes } from './local.ts';
export { KekRegistry } from './registry.ts';
export { AwsKmsKekProvider, awsKms, type AwsKmsOptions } from './aws-kms.ts';
export type { AwsCredentials } from './sigv4.ts';
