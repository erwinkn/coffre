import { z } from 'zod';

export const slug = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/);
export const displayName = z.string().trim().min(1).max(120);
export const secretKey = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/);
export const principalType = z.enum(['user', 'service']);
export const principalId = z.string().trim().min(1).max(320);
export const instanceRole = z.enum(['user', 'owner']);
export const grantId = z.string().uuid();
export const emailAddress = z.string().email().max(320);
export const isoDateTime = z.string().datetime();
export const syncId = z.string().uuid();
