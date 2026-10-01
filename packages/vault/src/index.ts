export type * from '@coffre/core/vault';
export { checkpointMessage, verifyCheckpoint } from '@coffre/core/vault';
export type { SecretContext } from '@coffre/core/envelope';
export { awsKms, KekUnavailableError } from '@coffre/core/kek';
export type { AwsCredentials, AwsKmsOptions, KekProvider, WrappedDek } from '@coffre/core/kek';
export type { Kek, VaultConfig } from './config.ts';
