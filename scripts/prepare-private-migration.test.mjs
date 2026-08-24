import assert from 'node:assert/strict';
import test from 'node:test';
import { migrationUrls } from './prepare-private-migration.mjs';

const owner = new URL('postgresql://10.84.0.12:5432/coffre?sslmode=require');
owner.username = 'coffre_owner';
owner.password = 'test-owner-password';

const valid = {
  caPath: '/tmp/coffre/database-ca.crt',
  expectedHost: '10.84.0.12',
  expectedPort: '5432',
  ownerUrl: owner.toString(),
  runtimePassword: 'runtime password',
  runtimeRole: 'coffre_runtime',
};

test('migration URLs keep owner access separate and force the checked CA', () => {
  const urls = migrationUrls(valid);
  const owner = new URL(urls.ownerUrl);
  const runtime = new URL(urls.runtimeUrl);

  assert.equal(owner.username, 'coffre_owner');
  assert.equal(owner.password, 'test-owner-password');
  assert.equal(owner.searchParams.get('sslmode'), 'verify-ca');
  assert.equal(owner.searchParams.get('sslrootcert'), valid.caPath);
  assert.equal(runtime.username, 'coffre_runtime');
  assert.equal(decodeURIComponent(runtime.password), valid.runtimePassword);
  assert.equal(runtime.hostname, valid.expectedHost);
});

test('migration URLs reject public, mismatched, and non-owner database targets', () => {
  assert.throws(() => migrationUrls({ ...valid, expectedHost: '203.0.113.10' }), /private/);
  assert.throws(() => migrationUrls({ ...valid, expectedHost: '10.84.0.13' }), /private/);
  assert.throws(() => migrationUrls({ ...valid, expectedPort: '6432' }), /PostgreSQL port/);
  assert.throws(() => migrationUrls({
    ...valid,
    ownerUrl: valid.ownerUrl.replace(':5432/', ':6432/'),
  }), /PostgreSQL port/);
  assert.throws(() => migrationUrls({
    ...valid,
    ownerUrl: valid.ownerUrl.replace('coffre_owner', 'coffre_runtime'),
  }), /coffre_owner/);
  assert.throws(() => migrationUrls({ ...valid, runtimeRole: 'postgres' }), /coffre_runtime/);
});
