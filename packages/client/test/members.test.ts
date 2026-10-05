import test from 'node:test';
import assert from 'node:assert/strict';

import { apiMember, serviceName, shownMember, shownText } from '@coffre/client';

test('a service account is service:<name> to people, and token:<name> to the API, as the log keeps it', () => {
  assert.equal(shownMember('token:deploy-slides'), 'service:deploy-slides');
  assert.equal(shownMember('user:ada@acme.example'), 'user:ada@acme.example');
  assert.equal(apiMember('service:deploy-slides'), 'token:deploy-slides');
  // The old form, still taken.
  assert.equal(apiMember('token:deploy-slides'), 'token:deploy-slides');
  assert.equal(apiMember('user:ada@acme.example'), 'user:ada@acme.example');
  for (const form of ['deploy', 'service:deploy', 'token:deploy']) assert.equal(serviceName(form), 'deploy');
  assert.equal(shownMember(apiMember('service:x')), 'service:x');
});

test("text from the API names service accounts as people do, and leaves the rest, a CI's id-token: write among it", () => {
  assert.equal(shownText('not a member: token:deploy'), 'not a member: service:deploy');
  assert.equal(shownText('`token:a` and (token:b)'), '`service:a` and (service:b)');
  assert.equal(shownText('give the job `permissions: id-token: write`'), 'give the job `permissions: id-token: write`');
  assert.equal(shownText('a bearer token: none came'), 'a bearer token: none came');
});
