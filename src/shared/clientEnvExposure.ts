import type { DetectedStack } from './types.js';
import { hasStack } from '../stack-detection/detectStack.js';

export type EnvAccessor = 'process.env' | 'import.meta.env' | 'other';

export type ClientBundleFramework = 'nextjs' | 'vite' | 'cra' | 'unknown';

export function clientBundleFramework(
  stack: DetectedStack,
  dependencyNames: ReadonlySet<string>,
): ClientBundleFramework {
  if (hasStack(stack, 'nextjs')) return 'nextjs';
  if (dependencyNames.has('react-scripts')) return 'cra';
  if (hasStack(stack, 'vite')) return 'vite';
  return 'unknown';
}

export function isEmbeddedInClientBundle(
  framework: ClientBundleFramework,
  accessor: EnvAccessor,
  name: string,
): boolean {
  switch (framework) {
    case 'nextjs':
      if (accessor === 'process.env') return name.startsWith('NEXT_PUBLIC_');
      return true;
    case 'cra':
      if (accessor === 'process.env') return name.startsWith('REACT_APP_');
      return true;
    case 'vite':
      if (accessor === 'import.meta.env') return name.startsWith('VITE_');
      return true;
    case 'unknown':
      return true;
  }
}

export const PUBLISHED_SECRET_NAME_PATTERN =
  /(SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD|PASSWD|AUTH_TOKEN|REFRESH_TOKEN|SIGNING|DATABASE_URL|CONNECTION_STRING)/;
