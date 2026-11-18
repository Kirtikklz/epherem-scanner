import { describe, expect, it } from 'vitest';
import { apiMutationWithoutAuth } from '../../src/rules/contextual/apiMutationWithoutAuth.js';
import { databaseDeleteWithoutOwnershipCheck } from '../../src/rules/contextual/databaseDeleteWithoutOwnershipCheck.js';
import { envUsageWithoutServerBoundary } from '../../src/rules/contextual/envUsageWithoutServerBoundary.js';
import { supabaseClientPrivilegedOperation } from '../../src/rules/contextual/supabaseClientPrivilegedOperation.js';
import { supabaseRlsNotDetected } from '../../src/rules/contextual/supabaseRlsNotDetected.js';
import { supabaseServiceRoleExposed } from '../../src/rules/basic/supabaseServiceRoleExposed.js';
import { loadFixtureContext } from './helpers.js';

describe('contextual rules', () => {
  it('api_mutation_without_auth flags unauthenticated mutations', async () => {
    const next = await loadFixtureContext('next-supabase-insecure');
    const nextFindings = apiMutationWithoutAuth.run(next);
    expect(nextFindings.some((finding) => finding.filePath.includes('app/api/admin'))).toBe(true);

    const express = await loadFixtureContext('express-cors-insecure');
    expect(apiMutationWithoutAuth.run(express)).toHaveLength(1);

    const clean = await loadFixtureContext('clean-basic-project');
    expect(apiMutationWithoutAuth.run(clean)).toHaveLength(0);
  });

  it('database_delete_without_ownership_check flags id-only deletes', async () => {
    const authed = await loadFixtureContext('next-authed-unscoped');
    const authedFindings = databaseDeleteWithoutOwnershipCheck.run(authed);
    expect(authedFindings.some((finding) => finding.filePath.includes('app/api/notes'))).toBe(true);

    const authedSql = await loadFixtureContext('express-authed-unscoped');
    const authedSqlFindings = databaseDeleteWithoutOwnershipCheck.run(authedSql);
    expect(authedSqlFindings).toHaveLength(1);
    expect(authedSqlFindings[0]?.filePath).toBe('server.js');

    const express = await loadFixtureContext('express-cors-insecure');
    expect(databaseDeleteWithoutOwnershipCheck.run(express)).toHaveLength(0);
  });

  it('supabase_client_used_for_privileged_operation flags browser-side updates', async () => {
    const context = await loadFixtureContext('next-supabase-insecure');
    const findings = supabaseClientPrivilegedOperation.run(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.filePath).toBe('components/ProfileCard.tsx');
    expect(findings[0]?.severity).toBe('high');
  });

  it('env_usage_without_server_boundary no longer claims Next.js inlines a non-public name', async () => {
    const context = await loadFixtureContext('next-supabase-insecure');
    expect(envUsageWithoutServerBoundary.run(context)).toHaveLength(0);
  });

  it('and the same line is still reported by the rule that owns it', async () => {
    const context = await loadFixtureContext('next-supabase-insecure');
    const findings = supabaseServiceRoleExposed.run(context);
    expect(findings.map((finding) => `${finding.filePath}:${finding.lineStart}`))
      .toContain('components/ProfileCard.tsx:8');
    expect(envUsageWithoutServerBoundary.run(context)
      .every((finding) => finding.filePath !== 'lib/supabaseAdmin.ts')).toBe(true);
  });

  it('contextual rules stay quiet on the clean project', async () => {
    const clean = await loadFixtureContext('clean-basic-project');
    for (const rule of [
      apiMutationWithoutAuth,
      databaseDeleteWithoutOwnershipCheck,
      supabaseClientPrivilegedOperation,
      supabaseRlsNotDetected,
      envUsageWithoutServerBoundary,
    ]) {
      expect(rule.run(clean), rule.id).toHaveLength(0);
    }
  });
});
