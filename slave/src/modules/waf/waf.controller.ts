import { Router, type Request, type Response, type RequestHandler } from 'express';
import { adminOnly } from './auth/keystone.middleware.js';
import { WafService } from './waf.service.js';
import {
  uuid,
  siteInput,
  sitePatch,
  originInput,
  policyInput,
  policyPatch,
  ruleInput,
  rulePatch,
  certificateInput,
  dto,
} from './validation.js';
import { HttpError } from './errors.js';

const id = (req: Request, name = 'id') => uuid.parse(req.params[name]);
const handle =
  (f: (req: Request, res: Response) => Promise<unknown>): RequestHandler =>
  (req, res, next) => {
    Promise.resolve(f(req, res)).catch(next);
  };
export function wafRouter(s: WafService) {
  const r = Router();
  r.get(
    '/sites',
    handle(async (q, p) => p.json({ sites: await s.listSites(q.ctx) })),
  );
  r.post(
    '/sites',
    handle(async (q, p) => p.status(202).json(await s.createSite(q.ctx, siteInput.parse(q.body)))),
  );
  r.get(
    '/sites/:id',
    handle(async (q, p) => p.json(await s.getSite(q.ctx, id(q)))),
  );
  r.patch(
    '/sites/:id',
    handle(async (q, p) => p.json(await s.updateSite(q.ctx, id(q), sitePatch.parse(q.body)))),
  );
  r.delete(
    '/sites/:id',
    handle(async (q, p) => {
      await s.deleteSite(q.ctx, id(q));
      p.status(202).json({ status: 'deleting' });
    }),
  );
  r.post(
    '/sites/:id/verify',
    handle(async (q, p) => p.status(202).json(await s.verifySite(q.ctx, id(q)))),
  );
  r.get(
    '/sites/:id/origins',
    handle(async (q, p) => p.json({ origins: await s.listOrigins(q.ctx, id(q)) })),
  );
  r.post(
    '/sites/:id/origins',
    handle(async (q, p) =>
      p.status(201).json(await s.addOrigin(q.ctx, id(q), originInput.parse(q.body))),
    ),
  );
  r.delete(
    '/sites/:id/origins/:originId',
    handle(async (q, p) => {
      await s.deleteOrigin(q.ctx, id(q), id(q, 'originId'));
      p.sendStatus(204);
    }),
  );
  r.get(
    '/policies',
    handle(async (q, p) => p.json({ policies: await s.listPolicies(q.ctx) })),
  );
  r.post(
    '/policies',
    handle(async (q, p) =>
      p.status(201).json(await s.createPolicy(q.ctx, policyInput.parse(q.body))),
    ),
  );
  r.get(
    '/policies/:id',
    handle(async (q, p) => p.json(dto(await s.policy(s.db, q.ctx, id(q))))),
  );
  r.patch(
    '/policies/:id',
    handle(async (q, p) => p.json(await s.updatePolicy(q.ctx, id(q), policyPatch.parse(q.body)))),
  );
  r.delete(
    '/policies/:id',
    handle(async (q, p) => {
      await s.deletePolicy(q.ctx, id(q));
      p.sendStatus(204);
    }),
  );
  r.get(
    '/policies/:id/rules',
    handle(async (q, p) => p.json({ rules: await s.listRules(q.ctx, id(q)) })),
  );
  r.post(
    '/policies/:id/rules',
    handle(async (q, p) =>
      p.status(201).json(await s.createRule(q.ctx, id(q), ruleInput.parse(q.body))),
    ),
  );
  r.patch(
    '/policies/:id/rules/:ruleId',
    handle(async (q, p) =>
      p.json(await s.updateRule(q.ctx, id(q), id(q, 'ruleId'), rulePatch.parse(q.body))),
    ),
  );
  r.delete(
    '/policies/:id/rules/:ruleId',
    handle(async (q, p) => {
      await s.deleteRule(q.ctx, id(q), id(q, 'ruleId'));
      p.sendStatus(204);
    }),
  );
  r.get(
    '/certificates',
    handle(async (q, p) => p.json({ certificates: await s.listCertificates(q.ctx) })),
  );
  r.post(
    '/certificates',
    handle(async (q, p) =>
      p.status(202).json(await s.createCertificate(q.ctx, certificateInput.parse(q.body))),
    ),
  );
  r.get(
    '/certificates/:id',
    handle(async (q, p) => p.json(dto(await s.certificate(s.db, q.ctx, id(q))))),
  );
  r.delete(
    '/certificates/:id',
    handle(async (q, p) => {
      await s.deleteCertificate(q.ctx, id(q));
      p.sendStatus(204);
    }),
  );
  r.get(
    '/nodes',
    adminOnly,
    handle(async (_q, p) => p.json({ nodes: await s.listNodes() })),
  );
  r.post(
    '/nodes/:id/drain',
    adminOnly,
    handle(async (q, p) => p.status(202).json(await s.drainNode(q.ctx, id(q)))),
  );
  // These phase-6 endpoints are explicitly unavailable until ingestion exists.
  // Never return fabricated traffic statistics or an apparently empty attack log.
  for (const path of ['/sites/:id/events', '/sites/:id/metrics'])
    r.get(
      path,
      handle(async (q) => {
        await s.site(s.db, q.ctx, id(q));
        throw new HttpError(
          501,
          'analytics_unavailable',
          'Analytics ingestion is not implemented yet',
        );
      }),
    );
  r.post(
    '/sites/:id/events/:eventId/exclude',
    handle(async (q) => {
      await s.site(s.db, q.ctx, id(q));
      throw new HttpError(
        501,
        'analytics_unavailable',
        'Event-based exclusions require analytics ingestion',
      );
    }),
  );
  return r;
}
