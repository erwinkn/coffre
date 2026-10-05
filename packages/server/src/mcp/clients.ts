import { ClientInvalid, clientFromDocument, isClientIdUrl, type ClientMetadata } from '@coffre/core/mcp';
import type { Database } from '@coffre/db';

import { findOauthClient } from '../db/queries.ts';
import { FetchRefused, type WorkloadTransport } from '../workloads/transport.ts';

/** How long a process keeps a client's metadata document. */
const DOCUMENT_MS = 10 * 60 * 1000;
/** Documents kept at once; past that, the oldest goes. */
const MAX_DOCUMENTS = 200;

/**
 * Documents fetched in this isolate or process, kept once they have
 * settled: never a fetch in flight, which on Workers belongs to the request
 * that started it. Two first asks fetch twice.
 */
const documents = new Map<string, { at: number; client: ClientMetadata }>();

const REGISTERED = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type ClientDeps = { db: Database; chainKey: Buffer; transport: WorkloadTransport; allowLoopback: boolean };

/** Whether resolving `clientId` would fetch: what the consent page's limiter counts. */
export function wouldFetch(clientId: string, allowLoopback: boolean, now = Date.now()): boolean {
  if (!isClientIdUrl(clientId, { allowLoopback })) return false;
  const kept = documents.get(clientId);
  return kept === undefined || now - kept.at >= DOCUMENT_MS;
}

/**
 * Who a `client_id` is: a Client ID Metadata Document, fetched through the
 * transport trust bindings use (no redirect, 5 seconds, 64 KiB, public
 * addresses only on Node), or a client that registered. Throws
 * `ClientInvalid`, saying why, for anything else.
 */
export async function resolveClient(deps: ClientDeps, clientId: string): Promise<ClientMetadata> {
  if (isClientIdUrl(clientId, { allowLoopback: deps.allowLoopback })) {
    const now = Date.now();
    const kept = documents.get(clientId);
    if (kept !== undefined && now - kept.at < DOCUMENT_MS) return kept.client;
    let document: unknown;
    try {
      document = await deps.transport.json(new URL(clientId));
    } catch (error) {
      if (error instanceof FetchRefused) throw new ClientInvalid(`the client's metadata document, ${error.message}`);
      throw error;
    }
    const client = clientFromDocument(clientId, document);
    documents.delete(clientId);
    documents.set(clientId, { at: now, client });
    while (documents.size > MAX_DOCUMENTS) documents.delete(documents.keys().next().value!);
    return client;
  }
  if (REGISTERED.test(clientId)) {
    const row = await findOauthClient(deps.db, deps.chainKey, clientId);
    if (row !== null) {
      return { clientId, name: row.name, host: null, redirectUris: JSON.parse(row.redirectUris) as string[], registration: 'dcr' };
    }
  }
  throw new ClientInvalid('the client_id is neither the HTTPS URL of a client metadata document nor a client registered here');
}

/** For tests: forget every document. */
export function forgetDocuments(): void {
  documents.clear();
}
