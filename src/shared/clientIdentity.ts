const IDENTITY_HEADER_NAMES: ReadonlySet<string> = new Set([
  'x-user-id',
  'x-userid',
  'x-user',
  'x-uid',
  'x-user-email',
  'x-useremail',
  'x-user-name',
  'x-username',
  'x-user-role',
  'x-userrole',
  'x-role',
  'x-roles',
  'x-is-admin',
  'x-isadmin',
  'x-admin',
  'x-account-id',
  'x-accountid',
  'x-customer-id',
  'x-member-id',
  'x-auth-user',
  'x-auth-user-id',
  'x-authenticated-user',
  'x-authenticated-user-id',
  'x-current-user',
  'x-current-user-id',
  'x-impersonate-user',
  'x-on-behalf-of',
  'user-id',
  'userid',
]);

export const HEADER_READ =
  /\bheaders\s*(?:\(\s*\))?\s*(?:\.\s*get\s*\(\s*|\[\s*)(['"`])([A-Za-z0-9_-]+)\1/g;

export function isSpoofableIdentityHeader(name: string): boolean {
  return IDENTITY_HEADER_NAMES.has(name.trim().toLowerCase());
}

const PRINCIPAL_FIELD_NAME =
  /^(?:userId|user_id|userID|userid|uid|currentUserId|current_user_id|currentUser|authUserId|auth_user_id|callerId|caller_id|actorId|actor_id|accountId|account_id|memberId|member_id|role|roles|userRole|user_role|isAdmin|is_admin|isSuperuser|is_superuser|isStaff|is_staff|permissions|accessLevel|access_level)$/;

export function isPrincipalFieldName(name: string): boolean {
  return PRINCIPAL_FIELD_NAME.test(name.trim());
}

export const REQUEST_PAYLOAD_EXPRESSION =
  /\b(?:await\s+)?(?:req|request|ctx\.request|event)\s*\.\s*(?:json\s*\(\s*\)|text\s*\(\s*\)|formData\s*\(\s*\)|body\b|query\b|params\b|queryStringParameters\b)/;

export const REQUEST_FIELD_READ =
  /\b(?:req|request|ctx\.request|event)\s*\.\s*(?:body|query|params|queryStringParameters)\s*\.\s*([A-Za-z_$][\w$]*)|\b(?:searchParams|formData|params|query)\s*\.\s*get\s*\(\s*['"`]([A-Za-z0-9_$-]+)['"`]\s*\)/g;

export const PRINCIPAL_LOOKUP =
  /\b(?:prisma|db|database|client|tx|trx|knex|models?)\s*\.\s*(?:users?|profiles?|accounts?|members?|staff|employees?|appUsers?|app_users?)\s*\.\s*(?:findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findOne|findById|findByPk|find)\s*\(|\b(?:User|Users|Profile|Profiles|Account|Accounts|Member|Members|Staff|Employee|Employees|AppUser)\s*\.\s*(?:findOne|findById|findByPk|findFirst|findUnique|find)\s*\(|\.\s*from\s*\(\s*['"`](?:public\.)?(?:users?|profiles?|accounts?|members?|staff|employees?|app_users?)['"`]\s*\)|\.\s*from\s*\(\s*(?:users?|profiles?|accounts?|members?)\s*\)|\bSELECT\b[\s\S]{0,200}?\bFROM\s+(?:public\.)?["'`]?(?:users?|profiles?|accounts?|members?|staff|employees?|app_users?)\b/gi;

export const PRIVILEGE_ATTRIBUTE =
  /\b(?:role|roles|permissions?|is_admin|isAdmin|is_superuser|isSuperuser|is_staff|isStaff|scopes?|privileges?|access_level|accessLevel|user_type|account_type|status)\b/;

export const PERMISSION_PREDICATE =
  /\b(?:hasPermission|hasRole|hasAnyRole|checkPermission|checkRole|requirePermission|requireRole|canAccess|isAdmin|isSuperAdmin|isStaff|authorizeUser|assertPermission|assertRole)\s*\(/;

export const AUTHORIZATION_REJECTION =
  /\bstatus\s*:\s*40[13]\b|\bstatus\s*\(\s*40[13]\s*\)|\b40[13]\b|\bUnauthorized\b|\bForbidden\b|\bNOT_AUTHORIZED\b|\bAccessDenied\b/i;

export const CREDENTIAL_VERIFICATION =
  /\bbcrypt\w*\s*\.\s*(?:compare|compareSync)\s*\(|\bargon2\s*\.\s*(?:verify|hash)\s*\(|\bscrypt\w*\s*\(|\bcompare(?:Password|Hash|Sync)\w*\s*\(|\b(?:verify|check|validate|match)Password\w*\s*\(|\bpassword\s*(?:===|==|!==|!=)|\b(?:oldPassword|old_password|currentPassword|current_password|passwordHash|password_hash)\b|\bpassport\s*\.\s*authenticate\s*\(|\bsignIn(?:WithPassword|WithOtp|WithOAuth)?\s*\(|\bverify(?:Otp|OTP|Code|Token|IdToken|Jwt|JWT|Session|Signature|Password|Credentials)\w*\s*\(|\bjwt\s*\.\s*verify\s*\(|\btotp\w*\s*\.\s*(?:verify|check)\s*\(|\bcreateHmac\s*\(/;

export const PRIVILEGE_COLUMN_NAME =
  /^(?:role|roles|is_admin|isadmin|admin|is_superuser|is_staff|permissions?|scopes?|privileges?|access_level|user_type|account_type)$/i;
