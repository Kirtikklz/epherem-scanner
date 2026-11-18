export type PythonRequirementsRole = 'requirements' | 'constraints';

const AROUND = (word: string): RegExp => new RegExp(`^(?:[a-z0-9]+[-_.])*${word}(?:[-_.][a-z0-9]+)*\\.txt$`);
const REQUIREMENTS_NAME = AROUND('requirements');
const CONSTRAINTS_NAME = AROUND('constraints');

export function pythonRequirementsRole(path: string): PythonRequirementsRole | undefined {
  const parts = path.replace(/\\/g, '/').toLowerCase().split('/');
  const name = parts[parts.length - 1] ?? '';
  if (CONSTRAINTS_NAME.test(name)) return 'constraints';
  if (REQUIREMENTS_NAME.test(name)) return 'requirements';
  if (parts.length >= 2 && parts[parts.length - 2] === 'requirements' && /^[^.].*\.txt$/.test(name)) {
    return 'requirements';
  }
  return undefined;
}

export function isPythonRequirementsPath(path: string): boolean {
  return pythonRequirementsRole(path) !== undefined;
}
