export interface RuleCatalogEntry {
  error: string;
  impact: string;
  impactWhenRead?: string;
}

export const RULE_CATALOG = {
  env_file_included: {
    error: 'Environment file may be exposed',
    impact: 'Anyone who receives this project can also receive the included environment file. If that file contains live API keys, database credentials or other secrets, those credentials can be copied and used outside the application; the finding does not establish that the file is publicly deployed.',
  },
  hardcoded_secret: {
    error: 'Secret or credential exposed in source code',
    impact: 'Anyone who obtains a copy of source code containing a live credential can copy and use that credential outside the application. What they can do depends on the secret: it could provide access to an API, database, cloud service or other account with the permissions attached to that credential.',
  },
  client_side_ai_secret: {
    error: 'AI provider access may be exposed to the browser',
    impact: 'If this AI-provider key is included in the deployed browser code, every visitor can copy it and use the provider account outside your application. They could consume the account\'s paid API usage or access whatever that particular key is authorised to access.',
  },
  supabase_service_role_exposed: {
    error: 'Supabase service role key exposed',
    impact: 'If the service-role key reaches the deployed browser code, or is sent back in a server response, anyone who sees it can copy it and make Supabase requests with its powerful permissions, including bypassing Row Level Security. Depending on the database permissions, that could allow reading, changing or deleting data; for the browser case, the scan cannot confirm what the final deployed bundle contains.',
  },
  firebase_open_rules: {
    error: 'Firebase security rules allow anonymous read or write access',
    impact: 'If these are the rules actually deployed to Firebase, anyone allowed by the public rule can read or change the data it covers without first proving who they are. The scan sees the rules included with the project, not the rules currently deployed, so the live Firebase configuration could differ.',
  },
  dangerous_cors_wildcard: {
    error: 'CORS policy is overly permissive',
    impact: 'An open CORS policy lets other websites read this API\'s responses from inside a visitor\'s browser. On its own that exposes nothing an anonymous request could not already get. It becomes serious when the server echoes back whichever website is asking and also accepts the visitor\'s login cookies, because a malicious site the user visits could then read their private data; browsers refuse that combination when the policy is the literal * wildcard.',
  },
  missing_security_headers: {
    error: 'Browser security headers are missing or weakened',
    impact: 'None of these gaps gives an attacker access to your application by itself. Missing or switched-off headers remove browser protections that limit attacks such as malicious scripts or clickjacking if another weakness exists, and an X-Powered-By header only tells visitors which framework you run; a CDN, reverse proxy or hosting platform may also set these headers outside the code Epherem can see.',
  },
  public_admin_route_hint: {
    error: 'Admin endpoint may be reachable by people who are not admins',
    impact: 'If this route really performs administrator-only work, someone without admin rights could use it: anyone who finds it when no sign-in check protects it, or any signed-in user when it checks sign-in but not the admin role. An admin-looking route name alone does not prove the route is sensitive, and protection outside the uploaded code would change this conclusion.',
  },
  sql_injection: {
    error: 'User input may allow SQL injection',
    impact: 'If attacker-controlled input can reach this query in the unsafe form Epherem detected, the attacker could change what the database command does. Depending on the database account\'s permissions, that could expose, change or delete data that the application was never meant to give them access to.',
  },
  command_injection: {
    error: 'User input may allow command injection',
    impact: 'If an attacker can control the input that reaches this operating-system command, they could make the server run commands the developer never intended. Those commands would run with the permissions of the application process and could potentially read data, alter files or take control of the service.',
  },
  path_traversal: {
    error: 'User input may allow path traversal',
    impact: 'If attacker-controlled input reaches this file path without effective validation, the attacker may be able to escape the directory the application intended to use and reach other files on the server. Depending on whether the operation reads or writes files, that could expose server data or overwrite files the application can access.',
  },
  ssrf: {
    error: 'User input may allow server-side request forgery',
    impact: 'If an attacker can control the destination of this server-side request, they may be able to make your server contact internal services, cloud metadata endpoints or other systems that are not normally reachable from the public internet. That can expose internal information or credentials if those services return them; network-level outbound restrictions can block some or all of these requests.',
  },
  open_redirect: {
    error: 'User input may allow an open redirect',
    impact: 'If an attacker can control this redirect destination, they can create a link on your legitimate domain that sends the person who clicks it to a site chosen by the attacker. That can make phishing or malware links look more trustworthy, but the redirect by itself does not give the attacker access to your users\' accounts or data.',
  },
  xss: {
    error: 'Unsanitized user input may allow XSS',
    impact: 'If attacker-controlled content reaches this HTML output without effective escaping or sanitisation, the attacker could run their own JavaScript inside another user\'s visit to your site. That script could act as that user or read information available to the page; how much it can steal or change depends on the application and its other browser protections.',
  },
  weak_jwt_handling: {
    error: 'JWT validation is insecure',
    impact: 'If the weakness Epherem found affects how these login tokens are verified, an attacker may be able to create, reuse or continue using a token that the application should reject. That could let them impersonate another user or keep access longer than intended; the exact risk depends on the JWT weakness involved.',
  },
  insecure_cookies: {
    error: 'Session cookies are insecure',
    impact: 'Depending on which cookie protections are missing, a session cookie may be easier to expose to scripts, send over an unsafe connection or use in a request started from another website. If the cookie identifies a logged-in user, those weaknesses can contribute to session theft or unwanted actions performed as that user.',
  },
  unsafe_file_upload: {
    error: 'File uploads are not adequately validated',
    impact: 'If no other layer restricts these uploads, a user may be able to send unexpected file types or files large enough to consume storage, processing time or bandwidth. More serious effects, such as scripts running in another user\'s browser or exploitation of a file-processing service, depend on what the application later does with the uploaded file.',
  },
  sensitive_data_in_logs: {
    error: 'Sensitive information may be written to logs',
    impact: 'Anyone who is able to view these logs (for example through a logging service, a compromised operations account or, for logs written in the browser, that browser\'s developer tools) may also be able to see the sensitive values written into them. If those values include live tokens or credentials they could be reused, while personal information could be exposed to people or systems that were never meant to receive it.',
  },
  debug_mode_enabled: {
    error: 'Debug mode is enabled',
    impact: 'If this debug or development setting is active in production, visitors may receive additional error details, internal configuration information or development-only behaviour that was not intended for them. That information can make other attacks easier, but the scan cannot confirm whether the same setting is active in the deployed environment.',
  },
  api_mutation_without_auth: {
    error: 'Missing authentication on API endpoints',
    impact: 'If no authentication layer outside the code Epherem can see protects this route, anyone who can reach it could trigger whatever the endpoint does without first proving who they are. Depending on the route, that could mean creating, changing or deleting data, sending messages, or using paid services on your account.',
  },
  database_delete_without_ownership_check: {
    error: 'Database deletion lacks an ownership check',
    impact: 'This delete is not tied to the signed-in user, so if the caller can influence which record it targets and ownership is not enforced elsewhere, a user could delete records that belong to someone else. Database-level Row Level Security can prevent this even when no ownership check is visible in the application code.',
  },
  supabase_client_used_for_privileged_operation: {
    error: 'Privileged database operation is exposed to client code',
    impact: 'If this operation relies on the browser being trusted and the database does not independently restrict it, a user can call the same operation directly and choose the values sent to Supabase. That could let them perform changes the interface did not intend to offer them; correctly configured Row Level Security can still block those changes.',
  },
  supabase_readable_sensitive_data: {
    error: 'Sensitive table is readable beyond its owners through a permissive RLS policy',
    impact: 'If this policy is active in the live database, people other than the owner of each row could read the sensitive information in the affected table: anyone at all when the policy allows public reads, or anyone who creates an account when it allows every signed-in user. That could expose personal information across many accounts at once; Epherem sees the SQL in the project, not later changes made directly to the live database.',
  },
  firebase_readable_sensitive_data: {
    error: 'Firestore collection with sensitive fields is readable without sign-in',
    impact: 'If this Firebase rule is deployed as shown, people who are not signed in could read the sensitive user information in the affected collection: every document when listing is allowed, or any single document whose ID they know or can guess when only single reads are allowed. The scan cannot confirm whether the uploaded rules are the ones currently deployed.',
  },
  supabase_rls_not_detected: {
    error: 'Row Level Security (RLS) was not detected',
    impact: 'This finding does not prove that your Supabase database is open. If the affected tables really do lack Row Level Security or another equivalent access control, users may be able to read or change rows beyond their own; Epherem cannot see RLS configured only in the Supabase dashboard, so this needs verification.',
  },
  env_usage_without_server_boundary: {
    error: 'Server secret may be exposed to frontend code',
    impact: 'If this environment value is included in the final browser bundle, every visitor can inspect and copy it. If the value is a secret, they could then use the service or account it protects; bundler behaviour such as removing unreachable code can sometimes prevent the value from actually reaching production.',
  },
  missing_webhook_verification: {
    error: 'Webhook signature is not verified',
    impact: 'If this webhook has no independent verification elsewhere, anyone who can reach the endpoint could send a request pretending to come from the real provider. They could trigger whatever actions the application trusts that webhook to perform, which might include changing orders, payments, accounts or other application state depending on the handler.',
  },
  broken_access_control: {
    error: 'Missing authorization checks',
    impact: 'If no database policy or other authorization layer checks ownership, a caller may be able to change a record ID and read or modify a record belonging to another user or tenant. The application can appear to require login while still failing to check whether the signed-in person is allowed to access that particular record.',
  },
  missing_rate_limit: {
    error: 'Sensitive endpoint has no rate limiting',
    impact: 'If no CDN, gateway or other layer rate-limits this endpoint, one person can send repeated requests as quickly as the service will accept them. On login or reset routes that can enable repeated guessing or spam, while expensive endpoints can consume server resources or increase costs; it does not make any individual request authorised when it otherwise would not be.',
  },
  missing_csrf_protection: {
    error: 'State-changing endpoint lacks CSRF protection',
    impact: 'If no effective CSRF protection exists elsewhere, a malicious website could cause a signed-in user\'s browser to send a state-changing request to your application using that user\'s cookies. The action would run with the victim\'s existing session even though they did not intend to perform it; browser cookie settings or custom checks Epherem cannot see may already prevent this.',
  },
  dependency_vulnerability: {
    error: 'A dependency has a known vulnerability',
    impact: 'This project installs a version of a package with a publicly documented security problem, so how to attack it is available to anyone who looks it up. For most advisories, harm depends on whether your code uses the vulnerable part of the package in a way an attacker can reach; if the advisory marks the package as malicious, it can do harm as soon as it is installed or loaded. The advisory listed with this finding describes what a successful attack does.',
  },
  public_cloud_storage: {
    error: 'A public Supabase or Firebase storage bucket was detected',
    impact: 'If this public-storage setting is active, anyone could reach the files it covers without the intended access check: retrieving files that were meant to be private, or, where public writing is allowed, uploading, replacing or deleting files. The impact depends on what the bucket stores, and Epherem cannot see configuration made only in the provider dashboard.',
  },
  verbose_error_response: {
    error: 'Production responses may expose internal error details',
    impact: 'If the deployed application sends these internal error details to users, a remote caller may learn information such as stack traces, file paths, database errors or implementation details. That information usually does not give access by itself, but it can reveal useful clues for finding or exploiting another weakness; Epherem cannot confirm the exact response produced by the live deployment.',
  },
  unsafe_dynamic_code: {
    error: 'Unsafe dynamic code execution was detected',
    impact: 'If attacker-controlled data reaches this dynamic code operation, it could be interpreted as code rather than ordinary data and run with the application\'s permissions. Epherem can see the dangerous code-execution pattern, but in some cases it cannot prove whether an attacker actually controls the value being evaluated.',
  },
  insecure_cryptography: {
    error: 'Insecure cryptography was detected',
    impact: 'If this weak cryptography is being used to protect passwords, tokens, signatures or confidential information, an attacker may have an easier way to guess, forge or recover the protected value. If the same algorithm is being used only for a non-security purpose such as a cache key, it may have no meaningful security impact.',
  },
  weak_password_storage: {
    error: 'Password storage appears weak or plaintext',
    impact: 'If your password database is stolen, weakly protected or plaintext passwords can be recovered much more easily and used to sign in as your users. Reused passwords can also put those users\' accounts on other services at risk; if password hashing happens elsewhere in code the scanner did not recognise, this finding may not apply.',
  },
  missing_request_body_validation: {
    error: 'Request body validation was not detected',
    impact: 'If the request body is not validated anywhere, a caller can send fields, types or values the application was not expecting. That can lead to invalid database writes, crashes or make another security flaw easier to exploit, but missing schema validation alone does not prove that an attacker can gain privileges or inject code.',
  },
  prototype_pollution: {
    error: 'Untrusted input may allow prototype pollution',
    impact: 'If an attacker controls the keys used by this object write or merge, they can set properties the code never meant to accept. In JavaScript that can reach properties shared by every object in the app, which becomes a security problem when later code relies on them for permissions or other sensitive decisions; in other languages the effect is limited to overwriting fields of the object being written.',
  },
  mass_assignment: {
    error: 'Untrusted fields may be mass-assigned',
    impact: 'If the affected model contains fields users should not be allowed to choose, a caller may be able to add those fields to a request and have the application save them anyway. Depending on the model, that could change values such as ownership, roles, permissions, prices or other protected properties; harmless models may have much less impact.',
  },
  unsafe_deserialization: {
    error: 'Unsafe deserialization was detected',
    impact: 'If an attacker can send crafted data into this deserialization code, the parser may create objects or behavior the application did not intend. In vulnerable libraries or configurations this can sometimes lead to data access or running attacker-controlled code, but the exact consequence depends on the deserializer and whether the attacker can reach it.',
  },
  unrestricted_graphql: {
    error: 'GraphQL operations may be unrestricted',
    impact: 'Depending on which problem was found, a caller could send unusually large or deeply nested queries that use up server or database resources and raise your costs, or, where schema discovery is switched on, download a full map of your API that makes its weak spots easier to find. Neither lets a caller see data they are not allowed to see; that is decided by the app\'s own login and permission checks.',
  },
  exposed_source_maps: {
    error: 'Production source maps may be exposed',
    impact: 'If these source maps are publicly deployed, anyone visiting the application may be able to recover more of the original source structure, file names, paths and comments than the normal production bundle reveals. That can make the application easier to study and may expose sensitive values accidentally left in source code, but a source map does not create access to secrets that are not present in it.',
  },
  dangerous_deployment_config: {
    error: 'Deployment configuration weakens runtime isolation',
    impact: 'Most of these settings do not let anyone in by themselves: they give an attacker who has already broken into the app more access to the machine and services around it. The exception is a database or remote-login port opened to the whole internet, which anyone can try to connect to directly, so its safety then rests entirely on that service\'s own password or key.',
  },
  nosql_injection: {
    error: 'User input may allow NoSQL injection',
    impact: 'If attacker-controlled data reaches this NoSQL query as query operators rather than ordinary values, the attacker could change which records the database matches. Depending on the affected operation, that could bypass a check, expose records the caller should not see or alter which records are changed.',
  },
  ldap_injection: {
    error: 'User input may allow LDAP injection',
    impact: 'If attacker-controlled input reaches this LDAP filter without safe handling, the attacker could change what the directory query searches for instead of supplying only an ordinary value. Depending on how the directory is used, that could expose records outside the intended search or interfere with an authentication check.',
  },
  xxe: {
    error: 'XML parser may allow external entity attacks',
    impact: 'If an attacker can supply XML to this parser and external entities are enabled as detected, they may be able to make the server read local files or send requests to other systems on its network. What can actually be exposed depends on the parser, the server\'s permissions and its network access.',
  },
  oauth_misconfiguration: {
    error: 'OAuth flow is weakly configured',
    impact: 'If the OAuth state or callback handling is actually weak, an attacker may be able to interfere with the sign-in flow, such as linking the wrong account, sending an authorization response somewhere unintended or abusing a login started by another user. The exact result depends on which part of the OAuth flow is misconfigured.',
  },
  weak_session_handling: {
    error: 'Session handling is insecure',
    impact: 'Depending on the session weakness detected, an attacker may be able to reuse, manipulate or take over a user\'s session and have the application treat them as that user. Session protection performed elsewhere in code that Epherem did not recognise could reduce or remove this risk.',
  },
  server_action_without_authorization: {
    error: 'Server action mutates data without an authorization check',
    impact: 'If no authorization check elsewhere protects this server action, a signed-in user could call it with another record\'s identifier or other chosen values and change data they are not meant to control. Database policies or permission checks hidden in helpers Epherem cannot follow could still prevent the change.',
  },
  client_controlled_authorization: {
    error: 'Authentication trusts a value the caller controls',
    impact: 'A caller who can choose the identity or privilege value used by this check could make the server apply permissions belonging to someone else instead of their own. Depending on the affected operation, that could let them read or change another user\'s data or gain higher privileges; an independent authorization layer outside the visible code could still prevent this.',
  },
  client_side_only_authorization: {
    error: 'Access control runs only in the browser',
    impact: 'If the browser check Epherem found is truly the only access control in the deployed app, a visitor could change the browser-owned identity value or bypass the screen and call the underlying functionality directly. That could expose pages, data or actions intended for signed-in users; protection enforced by infrastructure or database policies outside the uploaded project would change this conclusion.',
  },
  placeholder_authentication: {
    error: 'An authentication check is an unfinished placeholder',
    impact: 'Anything relying on this guard is not receiving the authentication or permission check its name implies. In most cases a caller who can reach it gets past the guard without logging in or holding the right permission, unless another independent layer protects the same route; if the unfinished guard instead refuses everyone, the feature behind it simply does not work.',
  },
  fail_open_authentication: {
    error: 'Authentication fails open \u2014 an error lets the request through',
    impact: 'Someone who can make this authentication check fail with an error may still reach the protected operation that follows instead of being rejected. Whatever that operation can read or change could then be available to a caller whose identity was never successfully verified.',
  },
  private_key_or_credential_file: {
    error: 'A file named like a private key or credential store is committed with the project',
    impact: 'A file whose name marks it as a private key or credential store is travelling with the project, so anyone who receives the project receives that file too. This finding is based on the file\'s name alone, and some such files (for example many .pem files) hold only a public certificate; if the file does contain a live key or credential, that person could use whatever systems or privileges it unlocks.',
  },
  data_artefact_committed: {
    error: 'A database dump or infrastructure state file is committed with the project',
    impact: 'A file whose name looks like a database copy or infrastructure-state file is travelling with the project, so anyone who receives the project receives that file too. Epherem has not opened it to confirm what it contains, but if it holds real customer data or live credentials, those values would be disclosed along with the source code.',
    impactWhenRead: 'A file whose name looks like a database copy or infrastructure-state file is travelling with the project, so anyone who receives the project receives that file too. Epherem read this file and found the marks of a database dump in it (a dump tool\'s header, COPY … FROM stdin, or many INSERT rows); if it holds real customer data or live credentials, those values would be disclosed along with the source code.',
  },
} as const satisfies Record<string, RuleCatalogEntry>;

export type CatalogRuleId = keyof typeof RULE_CATALOG;

export const NON_REGISTRY_RULE_IDS: ReadonlySet<CatalogRuleId> = new Set<CatalogRuleId>([
  'dependency_vulnerability',
  'private_key_or_credential_file',
  'data_artefact_committed',
]);

export const ARCHIVE_ENTRY_RULE_IDS: ReadonlySet<CatalogRuleId> = new Set<CatalogRuleId>([
  'private_key_or_credential_file',
  'data_artefact_committed',
]);

export function labelForRule(ruleId: string): string {
  if (Object.prototype.hasOwnProperty.call(RULE_CATALOG, ruleId)) {
    return RULE_CATALOG[ruleId as CatalogRuleId].error;
  }
  return `Security issue found by an uncatalogued rule (${ruleId})`;
}

export function impactForRule(ruleId: string): string | undefined {
  if (Object.prototype.hasOwnProperty.call(RULE_CATALOG, ruleId)) {
    return RULE_CATALOG[ruleId as CatalogRuleId].impact;
  }
  return undefined;
}
