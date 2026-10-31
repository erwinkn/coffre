// A use's connection closed by its deadline, in workerd (workers-socket.test.ts): its statement too big to write while
// the server reads nothing, as under backpressure.
import { createDatabase } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { sql } from 'drizzle-orm';

type Env = { DATABASE: string; CONTROL: string; BYTES: string };

export default {
  async fetch(_request: Request, env: Env): Promise<Response> {
    const pool = new HyperdrivePool(env.DATABASE);
    const db = createDatabase(pool);
    await db.execute(sql`select 1`);
    // The server stops reading: what is written from now on waits.
    await fetch(`${env.CONTROL}/pause`);
    const big = 'x'.repeat(Number(env.BYTES));
    const asked = db.execute(sql`select length(${big}) as n`).then(() => 'answered', () => 'failed');
    const by = Date.now() + 200;
    await pool.end(by);
    const past = Date.now() - by;
    // The request still under way, as a call's is while it answers: what the server reads now, it reads while workerd
    // could still send it (the end of a request would close the socket regardless).
    const read = await (await fetch(`${env.CONTROL}/ended`)).json();
    return Response.json({ query: await asked, past, read });
  },
};
