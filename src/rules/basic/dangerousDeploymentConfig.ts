import type { ScanRule } from '../../shared/types.js';
import { patternRule } from './patternRule.js';

export const dangerousDeploymentConfig: ScanRule = patternRule({
  id: 'dangerous_deployment_config',
  title: 'Deployment configuration weakens runtime isolation',
  category: 'configuration',
  extensions: new Set(['', '.yaml', '.yml', '.json', '.toml', '.tf']),
  probes: [
    {
      pattern: /\bprivileged\s*:\s*true\b|\ballowPrivilegeEscalation\s*:\s*true\b|\bhost(?:Network|PID|IPC)\s*:\s*true\b/g,
      title: 'privileged container setting', severity: 'critical', confidence: 'high',
      explanation: 'The deployment grants a container host-level privileges or namespace access. A compromise could escape normal workload isolation.',
      technical: 'A privileged/escalation/host-namespace option is enabled.',
      fix: 'Run unprivileged, set allowPrivilegeEscalation: false, drop all capabilities, use readOnlyRootFilesystem where possible, and avoid host namespaces.',
    },
    {
      pattern: /\bcap_add\s*:\s*(?:\[[^\]]*\bALL\b|[\s\S]{0,80}-\s*ALL\b)/gi,
      title: 'all Linux capabilities granted', severity: 'critical', confidence: 'high',
      explanation: 'The container receives all Linux capabilities, greatly increasing the impact of application compromise.',
      technical: 'cap_add includes ALL.',
      fix: 'Drop ALL capabilities and add back only the individual capability proven necessary.',
    },
    {
      pattern: /(?:0\.0\.0\.0\/0|::\/0)[\s\S]{0,100}\b(?:22|3306|5432|6379|27017)\b/g,
      title: 'management or database port open globally', severity: 'high', confidence: 'medium',
      explanation: 'A management or database port appears reachable from the entire internet.',
      technical: 'A world-open CIDR is associated with a sensitive service port.',
      fix: 'Remove public ingress; permit only private network ranges or a narrowly controlled administrative source through authenticated access.',
    },
    {
      pattern: /^\s*USER\s+root\s*$/gim,
      title: 'container runs as root', severity: 'high', confidence: 'high',
      explanation: 'The container is explicitly configured to run the application as root, increasing the impact of a compromise.',
      technical: 'The Dockerfile selects USER root for the resulting runtime stage.',
      fix: 'Create a dedicated unprivileged user, copy only required files with appropriate ownership, and set USER to that account in the final runtime stage.',
    },
  ],
  fileFilter: (path, content) => /(?:dockerfile|docker-compose|k8s|kubernetes|helm|deployment|service|terraform|vercel|netlify)/i.test(path) || /privileged|allowPrivilegeEscalation|hostNetwork|cap_add/i.test(content),
});
