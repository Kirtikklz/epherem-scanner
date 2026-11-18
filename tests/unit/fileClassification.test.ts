import { describe, expect, it } from 'vitest';
import { classifyFile } from '../../src/file-map/classifyFile.js';
import { memoryFile } from './helpers.js';

describe('classifyFile', () => {
  it.each([
    ['.env', 'API_KEY=abc', 'env'],
    ['.env.local', 'API_KEY=abc', 'env'],
    ['package.json', '{"dependencies":{}}', 'package_manifest'],
    ['package-lock.json', '{"lockfileVersion":3}', 'lockfile'],
    ['firestore.rules', 'allow read: if true;', 'firebase_rules'],
    ['supabase/config.toml', 'project_id = "x"', 'supabase_config'],
    ['migrations/001_init.sql', 'CREATE TABLE users();', 'migration'],
    ['prisma/schema.prisma', 'model User {}', 'database_schema'],
    ['middleware.ts', 'export function middleware() {}', 'middleware'],
    ['pages/api/users.ts', 'export default handler', 'api_route'],
    ['app/api/items/route.ts', 'export async function GET() {}', 'api_route'],
    ['lib/auth.ts', 'export function login() {}', 'auth'],
    ['next.config.js', 'module.exports = {};', 'config'],
    ['components/Button.tsx', 'export default () => <button />;', 'frontend_component'],
    ['scripts/tool.ts', 'export const x = 1;', 'unknown_useful'],
  ])('labels %s as %s', (filePath, content, expectedLabel) => {
    expect(classifyFile(memoryFile(filePath, content)).label).toBe(expectedLabel);
  });

  it('flags api/auth/db/middleware/env characteristics', () => {
    const entry = classifyFile(
      memoryFile(
        'app/api/admin/route.ts',
        "import { createClient } from '@supabase/supabase-js';\n" +
          "const supabase = createClient(process.env.SUPABASE_URL, process.env.KEY);\n" +
          "export async function GET() { await supabase.from('users').select('*'); }",
      ),
    );
    expect(entry.isLikelyApiRoute).toBe(true);
    expect(entry.isLikelyDatabaseRelated).toBe(true);
    expect(entry.usesEnvVariables).toBe(true);
    expect(entry.technologyHints).toContain('supabase');
  });

  it('detects express routes from content even outside route folders', () => {
    const entry = classifyFile(
      memoryFile('server.js', "const app = express();\napp.get('/health', (req, res) => res.send('ok'));"),
    );
    expect(entry.isLikelyApiRoute).toBe(true);
  });
});
