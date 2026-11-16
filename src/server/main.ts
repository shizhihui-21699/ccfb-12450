/**
 * Process entry point. Reads limits from the environment, binds the HTTP
 * server, and schedules quarantine retention sweeps.
 */
import { buildServer } from './index.ts';
import { loadLimits } from '../core/limits.ts';
import { RecordStore } from './store.ts';
import { join } from 'node:path';

const limits = loadLimits();
const port = Number(process.env.PORT ?? 8787);
const host = process.env.HOST ?? '127.0.0.1';
const dataDir = process.env.FILEGATE_DATA_DIR ?? join(process.cwd(), 'data');

const app = await buildServer({ limits, dataDir, logger: true });

// Public endpoint for the retention sweep; the same code path is reachable
// from the CLI for operators who prefer cron over an in-process timer.
const store = new RecordStore({ root: dataDir });
await store.init();
const sweep = async () => {
  try {
    const n = await store.purgeExpired(limits.retentionDays);
    if (n > 0) app.log.info({ purged: n }, 'retention sweep');
  } catch (e) {
    app.log.error({ err: e }, 'retention sweep failed');
  }
};
await sweep();
const timer = setInterval(sweep, 6 * 3600 * 1000);
timer.unref();

const shutdown = async () => {
  clearInterval(timer);
  await app.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

await app.listen({ port, host });
app.log.info({ port, host, dataDir, limits }, 'filegate listening');
