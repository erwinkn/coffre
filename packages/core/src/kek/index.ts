export type { KekProvider, WrappedDek } from './types.ts';
export { DEK_BYTES, KekUnavailableError } from './types.ts';
export { LocalKekProvider, equalBytes } from './local.ts';
export { KekRegistry } from './registry.ts';
export { AwsKmsKekProvider, awsKms, type AwsKmsOptions } from './aws-kms.ts';
export type { AwsCredentials } from './sigv4.ts';
