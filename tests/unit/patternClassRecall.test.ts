import { describe, expect, it } from 'vitest';
import { hardcodedSecret } from '../../src/rules/basic/hardcodedSecret.js';
import { sensitiveDataInLogs } from '../../src/rules/basic/sensitiveDataInLogs.js';
import { supabaseServiceRoleExposed } from '../../src/rules/basic/supabaseServiceRoleExposed.js';
import { memoryContext } from './helpers.js';

const NEXT = ['package.json', '{"dependencies":{"next":"14.0.0"}}'] as [string, string];
const run = (files: [string, string][], rule: { run: (context: never) => unknown }) =>
  rule.run(memoryContext(files) as never) as {
    filePath: string;
    lineStart: number;
    severity: string;
    technicalExplanation: string;
  }[];
const at = (findings: { filePath: string }[]) => findings.map((finding) => finding.filePath);

describe('supabase_service_role_exposed: a public NAME bound to a private VALUE', () => {
  it('fires when a build-time public name is assigned a service-role read', () => {
    const findings = run(
      [NEXT, ['next.config.mjs', 'export default {\n  env: {\n    NEXT_PUBLIC_ADMIN_BRIDGE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,\n  },\n};\n']],
      supabaseServiceRoleExposed,
    );
    expect(at(findings)).toContain('next.config.mjs');
  });

  it('stays quiet when the public name is assigned something that is not the service role', () => {
    const findings = run(
      [NEXT, ['next.config.mjs', 'export default {\n  env: {\n    NEXT_PUBLIC_SUPABASE_URL: process.env.SUPABASE_URL,\n  },\n};\n']],
      supabaseServiceRoleExposed,
    );
    expect(findings).toHaveLength(0);
  });

  it('stays quiet when a service-role read is bound to a correctly private name', () => {
    const findings = run(
      [NEXT, ['lib/admin.ts', 'const SUPABASE_ADMIN_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;\n']],
      supabaseServiceRoleExposed,
    );
    expect(findings).toHaveLength(0);
  });
});

describe('supabase_service_role_exposed: the key is in the response body', () => {
  it('fires when a route returns the service role key to its caller', () => {
    const findings = run(
      [
        NEXT,
        [
          'app/api/config/route.ts',
          "import { NextResponse } from 'next/server';\nexport async function GET() {\n  return NextResponse.json({\n    supabaseUrl: process.env.NEXT_PUBLIC_SUPABASE_URL,\n    supabaseKey: process.env.SUPABASE_SERVICE_ROLE_KEY,\n  });\n}\n",
        ],
      ],
      supabaseServiceRoleExposed,
    );
    expect(at(findings)).toContain('app/api/config/route.ts');
  });

  it('fires on the Express spelling of the same shape', () => {
    const findings = run(
      [
        ['package.json', '{"dependencies":{"express":"4.19.0"}}'],
        [
          'src/index.ts',
          "app.get('/v1/bootstrap', (_req, res) => {\n  res.json({\n    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,\n  });\n});\n",
        ],
      ],
      supabaseServiceRoleExposed,
    );
    expect(at(findings)).toContain('src/index.ts');
  });

  it('stays quiet when the key is read to BUILD a server client and never sent', () => {
    const findings = run(
      [
        NEXT,
        [
          'app/api/admin/route.ts',
          "import { createClient } from '@supabase/supabase-js';\nimport { NextResponse } from 'next/server';\nconst admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\nexport async function GET() {\n  const { data } = await admin.from('invoices').select('id');\n  return NextResponse.json({ data });\n}\n",
        ],
      ],
      supabaseServiceRoleExposed,
    );
    expect(findings).toHaveLength(0);
  });
});

describe('supabase_service_role_exposed: the key is a prop on a client component', () => {
  const METER_CLIENT = ['components/UsageMeter.tsx', "'use client';\nexport function UsageMeter({ bridgeKey }: { bridgeKey: string }) {\n  return <span>{bridgeKey.length}</span>;\n}\n"] as [string, string];
  const METER_SERVER = ['components/UsageMeter.tsx', 'export function UsageMeter({ bridgeKey }: { bridgeKey: string }) {\n  return <span>{bridgeKey.length}</span>;\n}\n'] as [string, string];
  const PAGE = "import { UsageMeter } from '@/components/UsageMeter';\nexport default function Page() {\n  return <UsageMeter bridgeKey={process.env.SUPABASE_SERVICE_ROLE_KEY!} seats={1} />;\n}\n";

  it('fires when the resolved component carries a "use client" directive', () => {
    const findings = run([NEXT, METER_CLIENT, ['app/dashboard/billing/page.tsx', PAGE]], supabaseServiceRoleExposed);
    expect(at(findings)).toContain('app/dashboard/billing/page.tsx');
  });

  it('stays quiet when the resolved component is a server component', () => {
    const findings = run([NEXT, METER_SERVER, ['app/dashboard/billing/page.tsx', PAGE]], supabaseServiceRoleExposed);
    expect(findings).toHaveLength(0);
  });

  it('stays quiet when the component cannot be resolved at all', () => {
    const findings = run(
      [
        NEXT,
        [
          'app/dashboard/billing/page.tsx',
          "import { UsageMeter } from '@vendor/widgets';\nexport default function Page() {\n  return <UsageMeter bridgeKey={process.env.SUPABASE_SERVICE_ROLE_KEY!} />;\n}\n",
        ],
      ],
      supabaseServiceRoleExposed,
    );
    expect(findings).toHaveLength(0);
  });
});

describe('hardcoded_secret: an intervening token is not a reason to stop looking', () => {
  it('fires through a Python type annotation', () => {
    const findings = run(
      [NEXT, ['app/config.py', 'class Settings(BaseSettings):\n    smtp_password: str = "Pm-8Qh3Vt62Xz9Ld4Ns0Wb7Rk1Yc5Fa"\n']],
      hardcodedSecret,
    );
    expect(at(findings)).toContain('app/config.py');
  });

  it('fires through a byte-decoding constructor across a line break', () => {
    const findings = run(
      [
        NEXT,
        [
          'packages/crypto.ts',
          "const COLUMN_KEY = Buffer.from(\n  '8f2b1c9d4e7a6053b1f8c2d94a7e6031c5b28d4f9e70a1638c2d5b4f7e91a06d',\n  'hex',\n);\n",
        ],
      ],
      hardcodedSecret,
    );
    expect(at(findings)).toContain('packages/crypto.ts');
  });

  it('stays quiet on a type declaration that binds no literal', () => {
    const findings = run([NEXT, ['types.ts', 'interface Login {\n  password: string;\n  token: string;\n}\n']], hardcodedSecret);
    expect(findings).toHaveLength(0);
  });
});

describe('hardcoded_secret: a key-named binding, and the labels that are not credentials', () => {
  it('fires on a long high-entropy literal bound to a name the old vocabulary missed', () => {
    const findings = run(
      [NEXT, ['lib/tokens.ts', "const PORTAL_SIGNING_KEY = 'pk_portal_9d41c7b0e25f4a83b6d1c04ef7a29b15';\n"]],
      hardcodedSecret,
    );
    expect(at(findings)).toContain('lib/tokens.ts');
  });

  it.each([
    ['a localStorage cache key', "const PERSISTED_CACHE_KEY = 'couple-space-media-url-cache-v2';"],
    ['a generated foreign-key name', 'const meta = { foreignKeyName: "stage01_clarification_returns_cycle_fk" };'],
    ['a versioned feature key', "const OFFICIAL_PRICE_MAP_CACHE_KEY = 'ppbears_official_price_map_daily_7am_v2';"],
  ])('stays quiet on %s — a value spelled out of words is a label', (_label, line) => {
    expect(run([NEXT, ['src/app.ts', `${line}\n`]], hardcodedSecret)).toHaveLength(0);
  });

  it('stays quiet on a 20-character high-entropy value — the wide name bar is paid for at 32', () => {
    const findings = run([NEXT, ['lib/session.ts', "const SESSION_KEY = 'x7Kq2Pd9Lm4Rt6Yw1Zs3';\n"]], hardcodedSecret);
    expect(findings).toHaveLength(0);
  });

  it('stays quiet on a UUID bound to a password-named constant — a published FIDO AAGUID', () => {
    const findings = run(
      [NEXT, ['shared/passkeys.ts', 'enum PasskeyBrand {\n  GooglePasswordManager = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",\n}\n']],
      hardcodedSecret,
    );
    expect(findings).toHaveLength(0);
  });

  it('stays quiet on a Stripe publishable key, which the vendor designs to be public', () => {
    const findings = run(
      [NEXT, ['lib/stripe.ts', ("export const PUBLISHABLE_KEY = 'pk" + "_test_51NqQmTGhKpLmXvWzRtYuIoPaSdFgHjKlZxCvBnM';\n")]],
      hardcodedSecret,
    );
    expect(findings).toHaveLength(0);
  });

  it('still fires on the SECRET half of the same pair', () => {
    const findings = run(
      [NEXT, ['lib/stripe.ts', ("const SECRET = 'sk" + "_live_51NqQmTGhKpLmXvWzRtYuIoPaSdFgHjKlZxCvBnMqWeRtYuIoP';\n")]],
      hardcodedSecret,
    );
    expect(at(findings)).toContain('lib/stripe.ts');
  });

  it.each([
    ['an IndexNow site-verification key', 'export const INDEXNOW_KEY = "7c4e9a2b8d6f15039e1a4c7b2d5e8f1a";'],
    ['a Web Push VAPID public key', "const firebaseVapidKey = 'BGeaAYWoNrfHHHE4g9lLol7Ae8mq8H_RktEKFzQiZvNF9ILLDjkmEYrDnJMS4d4BDwf2Wu6PeynXlamrrYbNO8';"],
  ])('stays quiet on %s — the protocol requires it to be published', (_label, line) => {
    expect(run([NEXT, ['src/seo.ts', `${line}\n`]], hardcodedSecret)).toHaveLength(0);
  });

  it('still fires when a published-key NAME holds a value that proves itself a credential', () => {
    const findings = run(
      [NEXT, ['src/seo.ts', ("const indexNowKey = 'sk" + "_live_51NqQmTGhKpLmXvWzRtYuIoPaSdFgHjKlZxCvBnMqWeRtYuIoP';\n")]],
      hardcodedSecret,
    );
    expect(at(findings)).toContain('src/seo.ts');
  });
});

describe('sensitive_data_in_logs: the fields are defined somewhere else', () => {
  const SPREAD = (fields: string) =>
    `const payload = {\n  ${fields}\n};\nlog.info('payout_destination_saved', { workspace: user.workspaceId, ...payload });\n`;

  it('fires when the spread object carries financial fields', () => {
    const findings = run(
      [NEXT, ['app/actions.ts', SPREAD("tax_id: form.get('tax_id'),\n  bank_account_number: form.get('bank'),\n  country: 'US',")]],
      sensitiveDataInLogs,
    );
    expect(at(findings)).toContain('app/actions.ts');
  });

  it('stays quiet when the spread object carries nothing sensitive', () => {
    const findings = run(
      [NEXT, ['app/actions.ts', SPREAD("country: 'US',\n  plan: 'studio',\n  seats: 4,")]],
      sensitiveDataInLogs,
    );
    expect(findings).toHaveLength(0);
  });

  it('stays quiet when the resolved fields are personal but not credential-grade', () => {
    const findings = run(
      [
        NEXT,
        [
          'app/host.tsx',
          "const gamePayload = {\n  latitude,\n  longitude,\n  address: form.address,\n  visibility: 'PUBLIC',\n};\nconsole.log('Game payload:', gamePayload);\n",
        ],
      ],
      sensitiveDataInLogs,
    );
    expect(findings).toHaveLength(0);
  });

  it('fires when a logged identifier holds the result of a SELECT projecting sensitive columns', () => {
    const findings = run(
      [
        NEXT,
        [
          'app/payout.py',
          'row = fetch_one("select p.legal_name, p.tax_id, p.bank_account_number from payout_settings p where p.id = %s", (pid,))\nlogger.info("payout snapshot for %s: %s", pid, row)\n',
        ],
      ],
      sensitiveDataInLogs,
    );
    expect(at(findings)).toContain('app/payout.py');
  });

  it('stays quiet when the SELECT projects only innocent columns', () => {
    const findings = run(
      [
        NEXT,
        [
          'app/payout.py',
          'row = fetch_one("select p.plan, p.country from payout_settings p where p.id = %s", (pid,))\nlogger.info("payout snapshot for %s: %s", pid, row)\n',
        ],
      ],
      sensitiveDataInLogs,
    );
    expect(findings).toHaveLength(0);
  });
});

describe('sensitive_data_in_logs: a house logger is a sink by EFFECT', () => {
  const WRAPPER = (forwarded: string) =>
    `export function record(event: string, fields: Record<string, unknown>) {\n  console.log(JSON.stringify({ at: Date.now(), event, ...${forwarded} }));\n}\n`;
  const CALLER =
    "import { record } from './log';\nexport async function POST({ request }) {\n  const { token, email } = await request.json();\n  record('portal_session_attempt', { token, email });\n}\n";

  it('fires through a wrapper that forwards its own parameter to console.log', () => {
    const findings = run([NEXT, ['routes/log.ts', WRAPPER('fields')], ['routes/session.ts', CALLER]], sensitiveDataInLogs);
    expect(at(findings)).toContain('routes/session.ts');
  });

  it('stays quiet through a wrapper that scrubs the same parameter', () => {
    const findings = run(
      [NEXT, ['routes/log.ts', WRAPPER('scrub(fields)')], ['routes/session.ts', CALLER]],
      sensitiveDataInLogs,
    );
    expect(at(findings)).not.toContain('routes/session.ts');
  });

  it('stays quiet when the import cannot be resolved to a module in the project', () => {
    const findings = run(
      [NEXT, ['routes/session.ts', CALLER.replace("'./log'", "'@acme/telemetry'")]],
      sensitiveDataInLogs,
    );
    expect(at(findings)).not.toContain('routes/session.ts');
  });
});
