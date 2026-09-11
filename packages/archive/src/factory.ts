import { R2AuditArchive, type AuditArchive } from './index';
import { S3AuditArchive } from './s3';
export interface ArchiveEnvironment { AUDIT_ARCHIVE?: R2Bucket; ARCHIVE_PROVIDER?: 'r2' | 's3'; S3_ENDPOINT?: string; S3_BUCKET?: string; S3_REGION?: string; S3_ACCESS_KEY_ID?: string; S3_SECRET_ACCESS_KEY?: string }
export function createArchive(env: ArchiveEnvironment): AuditArchive {
  if ((env.ARCHIVE_PROVIDER ?? 'r2') === 'r2') { if (!env.AUDIT_ARCHIVE) throw new Error('R2 audit binding is required'); return new R2AuditArchive(env.AUDIT_ARCHIVE); }
  if (env.ARCHIVE_PROVIDER === 's3' && env.S3_ENDPOINT && env.S3_BUCKET && env.S3_REGION && env.S3_ACCESS_KEY_ID && env.S3_SECRET_ACCESS_KEY) return new S3AuditArchive(env.S3_ENDPOINT, env.S3_BUCKET, env.S3_REGION, env.S3_ACCESS_KEY_ID, env.S3_SECRET_ACCESS_KEY);
  throw new Error('An audit archive must be explicitly configured');
}
