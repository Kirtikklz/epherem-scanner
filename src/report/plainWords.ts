export interface PlainWords {
  readonly title: string;
  readonly line: string;
}

export const PLAIN_CHECKS: Readonly<Record<string, PlainWords>> = {
  env_file_included: { title: 'An environment file (.env) is included in your project', line: 'This file usually holds your passwords and keys. Anyone who gets a copy of your project may get them too.' },
  hardcoded_secret: { title: 'A password or key is written directly in your code', line: 'Anyone who sees your code could copy it and use whatever it unlocks.' },
  client_side_ai_secret: { title: 'Your AI provider key may be visible to visitors', line: 'If it ends up in your website\'s code, anyone could copy it and run up your AI bill.' },
  supabase_service_role_exposed: { title: 'Your Supabase master key may be visible to visitors', line: 'This key skips all your database\'s protections. If visitors can see it, they could read, change or delete your data.' },
  firebase_open_rules: { title: 'Your Firebase data may be open to anyone', line: 'If these are your live rules, people could read or change that data without signing in.' },
  dangerous_cors_wildcard: { title: 'Other websites may be allowed to read your app\'s answers', line: 'Usually harmless on its own. It\'s risky when your app also accepts signed-in visitors\' cookies, because another site could then read their private data.' },
  missing_security_headers: { title: 'Some browser safety settings are missing', line: 'Not a way in by itself, but these settings help stop other attacks. Your hosting may already add them.' },
  public_admin_route_hint: { title: 'An admin route may be open to people who aren\'t admins', line: 'If it does admin-only work and nothing else protects it, someone without admin rights could use it.' },
  sql_injection: { title: 'Someone may be able to tamper with your database queries', line: 'If what people type reaches this query unsafely, they could read, change or delete data.' },
  command_injection: { title: 'Someone may be able to make your server run their own commands', line: 'If what people send reaches this command, they could run things on your server with your app\'s permissions.' },
  path_traversal: { title: 'Someone may be able to reach files on your server', line: 'If what people send is used as a file path without checks, they could read or overwrite files they shouldn\'t.' },
  ssrf: { title: 'Someone may be able to make your server visit any address', line: 'That could reach internal systems or cloud settings that are never meant to be public.' },
  open_redirect: { title: 'Links to your site could send people to another site', line: 'Scam links look more trustworthy when they start with your address. This alone doesn\'t give access to accounts.' },
  xss: { title: 'Someone may be able to run their own script on your pages', line: 'If what people submit is shown on a page unsafely, it could run in another visitor\'s browser and act as them.' },
  weak_jwt_handling: { title: 'Login tokens may not be checked properly', line: 'Someone could fake or reuse a login token and be treated as another user.' },
  insecure_cookies: { title: 'Login cookies are missing safety settings', line: 'They may be easier to steal or misuse, which can help someone take over a session.' },
  unsafe_file_upload: { title: 'File uploads aren\'t checked', line: 'People may upload unexpected or huge files. How serious this is depends on what your app does with them.' },
  sensitive_data_in_logs: { title: 'Passwords or personal data may be written to your logs', line: 'Anyone who can see the logs could see them too.' },
  debug_mode_enabled: { title: 'Debug mode is switched on', line: 'If it\'s on in your live app, visitors may see internal details that help attackers.' },
  api_mutation_without_auth: { title: 'A route that changes data doesn\'t check who\'s asking', line: 'If nothing else protects it, anyone could create, change or delete data through it.' },
  database_delete_without_ownership_check: { title: 'Deleting doesn\'t check who owns the record', line: 'A user might delete someone else\'s data, unless your database rules stop it.' },
  supabase_client_used_for_privileged_operation: { title: 'A powerful database action runs from the browser', line: 'Users could call it directly with their own values, unless your database rules (RLS) stop them.' },
  supabase_readable_sensitive_data: { title: 'Personal data in a table may be readable by other users', line: 'If this rule is live, other users, or anyone, could read personal information across many accounts.' },
  firebase_readable_sensitive_data: { title: 'Personal data in Firestore may be readable without signing in', line: 'If these rules are live, people who aren\'t signed in could read users\' personal data.' },
  supabase_rls_not_detected: { title: 'Database protection (Row Level Security) wasn\'t found', line: 'This doesn\'t prove your database is open: it may be set in the Supabase dashboard, so check there. Without it, users could read or change other users\' data.' },
  env_usage_without_server_boundary: { title: 'A secret setting may end up in your website\'s code', line: 'If it reaches the browser, visitors could copy it and use whatever it unlocks.' },
  missing_webhook_verification: { title: 'Incoming webhooks aren\'t checked to be real', line: 'Someone could send fake events, like a fake "payment received".' },
  broken_access_control: { title: 'Users may be able to open other users\' records', line: 'Changing an ID in a request could show or change someone else\'s data, unless other rules stop it.' },
  missing_rate_limit: { title: 'A sensitive route has no limit on repeated attempts', line: 'Someone could guess passwords over and over, spam it, or run up your costs.' },
  missing_csrf_protection: { title: 'Another website could make your users\' browsers act in your app', line: 'A malicious site could trigger actions in your app while a user is signed in, unless something else blocks it.' },
  dependency_vulnerability: { title: '{package} {version} has a known security problem', line: 'A library your app uses has a published security problem. Usually one update fixes it.' },
  public_cloud_storage: { title: 'A file storage bucket is public', line: 'Anyone may be able to get the files in it or, if writing is allowed, upload or delete files.' },
  verbose_error_response: { title: 'Error messages may show internal details', line: 'Visitors could see technical details that make other attacks easier.' },
  unsafe_dynamic_code: { title: 'Your code runs text as code', line: 'If someone can control that text, they could run their own code inside your app.' },
  insecure_cryptography: { title: 'An outdated way of scrambling data is used', line: 'If it protects passwords or tokens, they\'re easier to crack or fake.' },
  weak_password_storage: { title: 'Passwords may be stored without proper protection', line: 'If your database leaks, your users\' passwords could be read and reused.' },
  missing_request_body_validation: { title: 'Data people send isn\'t checked before it\'s used', line: 'Unexpected data could cause errors or bad records, and makes other attacks easier. Not a way in on its own.' },
  prototype_pollution: { title: 'Someone may be able to change settings shared across your app', line: 'In JavaScript this can affect permission checks elsewhere in your app.' },
  mass_assignment: { title: 'Users may be able to set fields they shouldn\'t, like their role', line: 'If a request can include extra fields, someone could change things like ownership, roles or prices.' },
  unsafe_deserialization: { title: 'Data is unpacked in an unsafe way', line: 'Specially crafted data could make your app misbehave, and sometimes run someone else\'s code.' },
  unrestricted_graphql: { title: 'Your GraphQL API has no limits on what can be asked', line: 'Huge requests could slow your app and raise costs, or reveal a map of your API.' },
  exposed_source_maps: { title: 'Your original source code may be downloadable', line: 'It makes your app easier to study, and exposes anything sensitive left in the code.' },
  dangerous_deployment_config: { title: 'Server settings give your app more access than it needs', line: 'Mostly matters after a break-in. A database port open to the internet is risky on its own.' },
  nosql_injection: { title: 'Someone may be able to change what your database searches for', line: 'They could get past a check or see records they shouldn\'t.' },
  ldap_injection: { title: 'Someone may be able to tamper with directory searches', line: 'They could see records outside the intended search, or interfere with a sign-in check.' },
  xxe: { title: 'Uploaded XML could make your server read its own files', line: 'Specially crafted XML could read files on your server or reach other systems.' },
  oauth_misconfiguration: { title: 'Sign-in with another service (OAuth) is set up weakly', line: 'Someone could interfere with sign-in, for example linking the wrong account.' },
  weak_session_handling: { title: 'Login sessions are handled unsafely', line: 'Someone could reuse or take over another user\'s session.' },
  server_action_without_authorization: { title: 'A server action changes records without checking who owns them', line: 'A signed-in user could change other people\'s data with it, unless your database rules stop it.' },
  client_controlled_authorization: { title: 'A permission check trusts who the caller says they are', line: 'Someone could claim to be another user, or an admin, and get their access.' },
  client_side_only_authorization: { title: 'Access is only checked in the browser', line: 'Visitors can get around browser-only checks and reach the pages, data or actions directly.' },
  placeholder_authentication: { title: 'A permission check is an unfinished placeholder', line: 'In most cases it lets everyone through. Finish it before you launch.' },
  fail_open_authentication: { title: 'An error in the sign-in check lets people through', line: 'If the check breaks, people get in instead of being stopped.' },
  private_key_or_credential_file: { title: 'A key or password file is in your project', line: 'Judged by its name only. If it holds a real key, anyone with your project could use it.' },
  data_artefact_committed: { title: 'A database copy or server file is in your project', line: 'If it holds real customer data or passwords, anyone with your project gets them.' },
};

export const PLAIN_VARIANTS: readonly (PlainWords & { readonly check: string; readonly placeTitle: string })[] = [
  { check: 'missing_security_headers', placeTitle: 'Server advertises its framework in X-Powered-By',
    title: 'Your server tells visitors which framework it runs',
    line: 'Not a way in by itself, but it gives attackers a clue. Your hosting may already hide it.' },
  { check: 'insecure_cryptography', placeTitle: 'Insecure cryptography is used: predictable security token',
    title: 'A security token is made in a guessable way',
    line: 'If it protects sign-ins, password resets or links, someone could guess it.' },
  { check: 'insecure_cryptography', placeTitle: 'Insecure cryptography is used: predictable account-recovery token',
    title: 'A security token is made in a guessable way',
    line: 'If it protects sign-ins, password resets or links, someone could guess it.' },
  { check: 'unrestricted_graphql', placeTitle: 'GraphQL server permits unrestricted operations: production discovery feature enabled',
    title: 'Your GraphQL API shares a full map of itself',
    line: 'Not a way in by itself, but it makes weak spots easier to find.' },
];

const PACKAGE_RULE = 'dependency_vulnerability';

export function plainPackageTitle(name: string, versions: readonly string[]): string {
  const v = versions.filter((x) => typeof x === 'string' && x !== '');
  return PLAIN_CHECKS[PACKAGE_RULE]!.title
    .replace('{package}', () => name)
    .replace(v.length > 0 ? '{version}' : ' {version}', () => v.join(', '));
}

export function plainWordsForFinding(
  ruleId: string,
  placeTitles: readonly string[],
  pkg: { readonly name: string; readonly versions: readonly string[] } | null,
): PlainWords | null {
  const words = Object.prototype.hasOwnProperty.call(PLAIN_CHECKS, ruleId) ? PLAIN_CHECKS[ruleId]! : null;
  if (words === null) return null;
  if (ruleId === PACKAGE_RULE) {
    if (pkg === null || pkg.name === '') return null;
    return { title: plainPackageTitle(pkg.name, pkg.versions), line: words.line };
  }
  for (const variant of PLAIN_VARIANTS) {
    if (variant.check === ruleId && placeTitles.length > 0 && placeTitles.every((t) => t === variant.placeTitle)) {
      return { title: variant.title, line: variant.line };
    }
  }
  return { title: words.title, line: words.line };
}
