import { spawn } from 'node:child_process';
import { HttpError } from '../errors.js';

export function lintRaw(binary: string) {
  return async (seclang: string) => {
    // Administrator rules may inspect/act, but cannot change filesystem, audit,
    // network, or engine configuration. Child input is never passed through a shell.
    const logical = seclang.replace(/\\\r?\n/g, ' ');
    for (const line of logical
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s && !s.startsWith('#')))
      if (!/^(SecRule|SecAction|SecMarker)\s/.test(line))
        throw new HttpError(
          422,
          'invalid_rule',
          'Raw rules may only contain SecRule, SecAction, and SecMarker',
        );
    const ids = [...logical.matchAll(/\bid\s*:\s*'?([0-9]+)/gi)];
    if (!ids.length || ids.some((m) => +m[1] < 9000001 || +m[1] > 9099999))
      throw new HttpError(
        422,
        'invalid_rule',
        'Custom rule IDs must be between 9000001 and 9099999',
      );
    await lintCompiled(binary, seclang, false);
  };
}

export async function lintCompiled(binary: string, seclang: string, full = true) {
  await new Promise<void>((resolve, reject) => {
    const child = spawn(binary, full ? ['-full'] : [], {
      stdio: ['pipe', 'ignore', 'ignore'],
      timeout: 10000,
    });
    child.on('error', () =>
      reject(new HttpError(503, 'lint_unavailable', 'Rule compiler is unavailable')),
    );
    child.on('close', (code) =>
      code === 0
        ? resolve()
        : reject(new HttpError(422, 'invalid_rule', 'Coraza rejected this SecLang configuration')),
    );
    child.stdin.on('error', () => {});
    child.stdin.end(seclang);
  });
}
