import { z } from 'zod';
import { LocalKeyProvider, ServiceKeyProvider, unb64, type KmsBinding } from './index';
import { ScalewayKeyProvider } from './scaleway';
import { HttpKmsBinding } from './remote';
import type { KeyProvider } from '../../contracts/src/index';
export interface KeyEnvironment { KEY_PROVIDER: 'local' | 'scaleway' | 'service' | 'remote'; ROOT_KEYS?: string; SCW_CURRENT_KEY?: string; SCW_ALLOWED_KEYS?: string; SCW_SECRET_KEY?: string; KMS?: KmsBinding; KMS_URL?: string; KMS_ACCESS_CLIENT_ID?: string; KMS_ACCESS_CLIENT_SECRET?: string }
export function createKeyProvider(env: KeyEnvironment): KeyProvider {
  switch (env.KEY_PROVIDER) {
    case 'local': {
      const ring = z.object({ current: z.string().min(1), keys: z.record(z.string(), z.string()) }).strict().parse(JSON.parse(env.ROOT_KEYS ?? 'null'));
      return new LocalKeyProvider(new Map(Object.entries(ring.keys).map(([id, value]) => [id, unb64(value)])), ring.current);
    }
    case 'scaleway': return new ScalewayKeyProvider(env.SCW_CURRENT_KEY ?? '', z.array(z.string()).parse(JSON.parse(env.SCW_ALLOWED_KEYS ?? 'null')), env.SCW_SECRET_KEY ?? '');
    case 'service': if (!env.KMS) throw new Error('KMS binding is required'); return new ServiceKeyProvider(env.KMS);
    case 'remote': return new ServiceKeyProvider(new HttpKmsBinding(env.KMS_URL ?? '', env.KMS_ACCESS_CLIENT_ID ?? '', env.KMS_ACCESS_CLIENT_SECRET ?? ''));
    default: throw new Error('Unknown key provider; no fallback is permitted');
  }
}
