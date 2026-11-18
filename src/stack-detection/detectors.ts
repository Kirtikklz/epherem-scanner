import type { Confidence, FileMap, StackDetection, StackName } from '../shared/types.js';
import { basename } from '../shared/utils.js';
import { collectDependencies } from './collectDependencies.js';

interface DetectionEvidence {
  description: string;
  strength: Confidence;
}

interface StackProbe {
  name: StackName;
  dependencies: string[];
  filePatterns: { pattern: RegExp; description: string }[];
  contentPatterns: { pattern: RegExp; description: string; inFiles?: RegExp }[];
}

const STACK_PROBES: StackProbe[] = [
  {
    name: 'nextjs',
    dependencies: ['next'],
    filePatterns: [{ pattern: /^next\.config\.(js|ts|mjs)$/, description: 'next.config file present' }],
    contentPatterns: [{ pattern: /from\s+['"]next\//, description: 'imports from next/*' }],
  },
  {
    name: 'react',
    dependencies: ['react'],
    filePatterns: [],
    contentPatterns: [{ pattern: /from\s+['"]react['"]/, description: 'imports react' }],
  },
  {
    name: 'nodejs',
    dependencies: [],
    filePatterns: [{ pattern: /^package\.json$/, description: 'package.json present' }],
    contentPatterns: [],
  },
  {
    name: 'express',
    dependencies: ['express'],
    filePatterns: [],
    contentPatterns: [{ pattern: /require\(['"]express['"]\)|from\s+['"]express['"]/, description: 'imports express' }],
  },
  {
    name: 'supabase',
    dependencies: ['@supabase/supabase-js', '@supabase/ssr', '@supabase/auth-helpers-nextjs', 'supabase'],
    filePatterns: [
      { pattern: /(^|\/)supabase\/config\.toml$/, description: 'supabase config.toml present' },
      {
        pattern: /(^|\/)supabase\/(migrations\/[^/]+\.sql|seed\.sql|functions\/.+)$/,
        description: 'supabase project folder present',
      },
    ],
    contentPatterns: [
      { pattern: /@supabase\/|SUPABASE_(URL|ANON_KEY|SERVICE_ROLE_KEY)/, description: 'supabase imports or env vars' },
      {
        pattern: /(^|[^\w$."])"?auth"?\."?(uid|jwt)"?\s*\(\s*\)/im,
        description: 'supabase auth functions in SQL',
        inFiles: /\.sql$/i,
      },
      {
        pattern: /^[ \t]+supabase(_flutter)?[ \t]*:/m,
        description: 'supabase dependency in pubspec.yaml',
        inFiles: /(^|\/)pubspec\.yaml$/,
      },
      {
        pattern: /package:supabase(_flutter)?\//,
        description: 'supabase dart import',
        inFiles: /\.dart$/,
      },
      {
        pattern: /^[ \t]*["']?supabase[ \t]*(\[[^\]\n]*\])?[ \t]*([=<>!~;@#"']|$)/m,
        description: 'supabase python requirement',
        inFiles: /(^|\/)(requirements[^/]*\.txt|pyproject\.toml)$/,
      },
      {
        pattern: /^[ \t]*(from[ \t]+supabase(\.[\w.]+)?[ \t]+import\b|import[ \t]+supabase\b)/m,
        description: 'supabase python import',
        inFiles: /\.py$/,
      },
    ],
  },
  {
    name: 'firebase',
    dependencies: ['firebase', 'firebase-admin', 'firebase-functions'],
    filePatterns: [{ pattern: /^(firebase\.json|firestore\.rules|storage\.rules|database\.rules\.json|\.firebaserc)$/, description: 'firebase project file present' }],
    contentPatterns: [{ pattern: /['"]firebase(-admin)?\/|getFirestore|initializeApp\s*\(/, description: 'firebase SDK usage' }],
  },
  {
    name: 'python',
    dependencies: [],
    filePatterns: [
      { pattern: /\.py$/, description: 'python source files present' },
      { pattern: /^(requirements\.txt|pyproject\.toml)$/, description: 'python dependency manifest present' },
    ],
    contentPatterns: [],
  },
  {
    name: 'fastapi',
    dependencies: [],
    filePatterns: [],
    contentPatterns: [{ pattern: /from\s+fastapi\s+import|FastAPI\(|^fastapi\b/m, description: 'fastapi usage' }],
  },
  {
    name: 'flask',
    dependencies: [],
    filePatterns: [],
    contentPatterns: [{ pattern: /from\s+flask\s+import|Flask\(__name__\)|^flask\b/m, description: 'flask usage' }],
  },
  {
    name: 'django',
    dependencies: [],
    filePatterns: [],
    contentPatterns: [
      { pattern: /^[ \t]*(?:from[ \t]+django(?:\.[\w.]+)?[ \t]+import\b|import[ \t]+django\b)/m, description: 'django import', inFiles: /\.py$/ },
      { pattern: /\bDJANGO_SETTINGS_MODULE\b/, description: 'manage.py names a Django settings module', inFiles: /(?:^|\/)manage\.py$/ },
    ],
  },
  {
    name: 'prisma',
    dependencies: ['prisma', '@prisma/client'],
    filePatterns: [{ pattern: /schema\.prisma$/, description: 'prisma schema present' }],
    contentPatterns: [{ pattern: /PrismaClient/, description: 'PrismaClient usage' }],
  },
  {
    name: 'drizzle',
    dependencies: ['drizzle-orm', 'drizzle-kit'],
    filePatterns: [{ pattern: /^drizzle\.config\.(ts|js)$/, description: 'drizzle config present' }],
    contentPatterns: [{ pattern: /drizzle-orm/, description: 'drizzle-orm imports' }],
  },
  {
    name: 'tailwind',
    dependencies: ['tailwindcss'],
    filePatterns: [{ pattern: /^tailwind\.config\.(js|ts|mjs|cjs)$/, description: 'tailwind config present' }],
    contentPatterns: [],
  },
  {
    name: 'vite',
    dependencies: ['vite'],
    filePatterns: [{ pattern: /^vite\.config\.(js|ts|mjs)$/, description: 'vite config present' }],
    contentPatterns: [],
  },
  {
    name: 'ai_agent_mcp',
    dependencies: [
      '@modelcontextprotocol/sdk', 'openai', '@anthropic-ai/sdk', 'ai',
      'langchain', '@langchain/core', 'llamaindex',
    ],
    filePatterns: [{ pattern: /^(mcp\.json|\.mcp\.json)$/, description: 'MCP manifest present' }],
    contentPatterns: [
      { pattern: /@modelcontextprotocol\/|from\s+openai\s+import|from\s+anthropic\s+import|langchain/, description: 'AI agent / MCP SDK usage' },
    ],
  },
];

export function probeStacks(fileMap: FileMap): StackDetection[] {
  const dependencies = new Map(
    collectDependencies(fileMap).map((dependency) => [dependency.name, dependency.source]),
  );
  const detections: StackDetection[] = [];

  for (const probe of STACK_PROBES) {
    const evidence: DetectionEvidence[] = [];

    for (const dependency of probe.dependencies) {
      const manifestPath = dependencies.get(dependency);
      if (manifestPath !== undefined) {
        evidence.push({ description: `dependency "${dependency}" in ${manifestPath}`, strength: 'high' });
      }
    }
    for (const filePattern of probe.filePatterns) {
      const match = fileMap.entries.find(
        (entry) => filePattern.pattern.test(basename(entry.path)) || filePattern.pattern.test(entry.path),
      );
      if (match !== undefined) {
        evidence.push({ description: `${filePattern.description} (${match.path})`, strength: 'high' });
      }
    }
    for (const contentPattern of probe.contentPatterns) {
      const { inFiles } = contentPattern;
      const match = fileMap.entries.find(
        (entry) => (inFiles === undefined || inFiles.test(entry.path)) && contentPattern.pattern.test(entry.content),
      );
      if (match !== undefined) {
        evidence.push({ description: `${contentPattern.description} (${match.path})`, strength: 'medium' });
      }
    }

    if (evidence.length === 0) continue;
    const confidence: Confidence = evidence.some((item) => item.strength === 'high') ? 'high' : 'medium';
    detections.push({
      name: probe.name,
      confidence,
      evidence: evidence.map((item) => item.description),
    });
  }

  return detections;
}
