import express, { type ErrorRequestHandler } from 'express';
import { ZodError } from 'zod';
import { sql } from 'drizzle-orm';
import { keystoneAuth } from './modules/waf/auth/keystone.middleware.js';
import { wafRouter } from './modules/waf/waf.controller.js';
import { WafService } from './modules/waf/waf.service.js';
import { HttpError } from './modules/waf/errors.js';
import { openapi } from './openapi.js';

export function createApp(
  service: WafService,
  auth: { url: string; serviceToken: () => Promise<string> },
) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  app.use((_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.set('X-Content-Type-Options', 'nosniff');
    next();
  });
  app.use(express.json({ limit: '256kb' }));
  app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));
  app.get('/readyz', async (_req, res) => {
    try {
      await service.db.execute(sql`select 1`);
      res.json({ status: 'ready' });
    } catch {
      res.status(503).json({ status: 'unavailable' });
    }
  });
  app.get('/openapi.json', (_req, res) => res.json(openapi()));
  const authMiddleware = keystoneAuth(auth.url, auth.serviceToken);
  app.use('/v1/waf', authMiddleware, wafRouter(service));
  app.use('/waf/v1', authMiddleware, wafRouter(service));
  app.use((_req, _res, next) => next(new HttpError(404, 'not_found', 'Endpoint not found')));
  const onError: ErrorRequestHandler = (err, _req, res, _next) => {
    if (err instanceof HttpError) {
      res
        .status(err.status)
        .json({
          error: {
            code: err.code,
            message: err.message,
            ...(err.details ? { details: err.details } : {}),
          },
        });
      return;
    }
    if (err instanceof ZodError) {
      res
        .status(422)
        .json({
          error: {
            code: 'validation_error',
            message: 'Request validation failed',
            details: err.issues.map((i) => ({ path: i.path, message: i.message })),
          },
        });
      return;
    }
    if (err?.type === 'entity.parse.failed') {
      res.status(400).json({ error: { code: 'invalid_json', message: 'Malformed JSON' } });
      return;
    }
    if (err?.type === 'entity.too.large') {
      res
        .status(413)
        .json({ error: { code: 'body_too_large', message: 'Request body exceeds 256 KiB' } });
      return;
    }
    const code = err?.cause?.code ?? err?.code;
    if (code === '23505' || code === '23503') {
      res
        .status(409)
        .json({
          error: { code: 'conflict', message: 'Resource conflicts with existing configuration' },
        });
      return;
    }
    // Do not serialize database queries, tokens, PEMs, or driver connection strings.
    console.error(
      JSON.stringify({
        level: 'error',
        message: 'WAF operation failed',
        type: err?.name ?? 'Error',
        code: typeof code === 'string' ? code : undefined,
      }),
    );
    res
      .status(500)
      .json({ error: { code: 'internal_error', message: 'Unable to complete request' } });
  };
  app.use(onError);
  return app;
}
