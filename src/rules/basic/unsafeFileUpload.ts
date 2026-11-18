import { makeFinding } from '../../shared/findingFactory.js';
import type { Finding, RuleContext, ScanRule } from '../../shared/types.js';
import { findMatches } from '../../shared/utils.js';
import { windowAround } from '../../shared/userInput.js';
import { inPythonProse } from '../../shared/pythonScope.js';
import { fastapiUploads, flaskBodyCapSet, pythonNameIsStoredRecord, pythonUploadDefLine, pythonUploadFacts, type UploadFacts } from '../../shared/pythonUpload.js';

const CODE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

const UPLOAD_SINK =
  /\bmulter\s*\(([\s\S]{0,220}?)\)|\bnew\s+multer|\bupload\.(?:single|array|fields|any)\s*\(|formidable\s*\(|busboy\s*\(|\.(?:mv|move)\s*\(|request\.files\b|createReadStream\([^)]*\)\.pipe|\bpath\s*\.\s*(?:join|resolve)\s*\((?![^\n)]*\b(?:basename|sanitize|slugify)\s*\()[^)\n]*\b\w*(?:file|upload|attachment)\w*\s*\.\s*(?:name|filename|originalname|originalFilename)\b/g;
const TYPE_GUARD = /fileFilter|allowedTypes|mimetype|accept\b|extname|whitelist|allowlist/i;
const SIZE_GUARD = /limits\s*:|fileSize|maxFileSize|maxSize/i;

const REQUEST_BORNE_FILE =
  /\bmulter\b|\bformidable\b|\bbusboy\b|\bmultiparty\b|\bexpress-fileupload\b|\bdicer\b|\bfileUpload\s*\(|\b(?:req|request|ctx|event)\s*\.\s*files?\b|multipart\/form-data|\bformData\s*\(\s*\)|\bFormData\b|\.\s*get\s*\(\s*['"][^'"]*file[^'"]*['"]\s*\)|\bfiles\s*\[\s*0\s*\]|\bacceptedFiles\b|\bUploadedFile\b|\bMultipartFile\b|\brequest\.form\b|\bawait\s+req\w*\.formData\b/i;

export const unsafeFileUpload: ScanRule = {
  id: 'unsafe_file_upload',
  title: 'File upload without type/size restrictions',
  category: 'file_upload',
  kind: 'basic',
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const entry of context.fileMap.entries) {
      if (!CODE_EXTENSIONS.has(entry.extension)) continue;
      const isPython = entry.extension === '.py';
      const gated = REQUEST_BORNE_FILE.test(entry.content);
      if (!gated && !isPython) continue;
      const seen = new Set<number>();
      for (const match of gated ? findMatches(entry.content, UPLOAD_SINK) : []) {
        if (seen.has(match.line)) continue;
        let facts: UploadFacts | undefined;
        if (isPython) {
          if (inPythonProse(entry.content, match.index)) continue;
          const joined = /\b(\w+)\s*\.\s*\w+$/.exec(match.matchText);
          if (/^path\s*\./.test(match.matchText) && joined !== null && pythonNameIsStoredRecord(entry, match.line, joined[1]!)) continue;
          facts = pythonUploadFacts(entry, match.line);
        }
        const scope = windowAround(entry.content, match.index, 320);
        const missing: string[] = [];
        if (!TYPE_GUARD.test(scope) && facts?.typeChecked !== true) missing.push('allowed file types');
        if (!SIZE_GUARD.test(scope) && facts?.sizeChecked !== true && !(isPython && flaskBodyCapSet(context.fileMap.entries))) missing.push('a size limit');
        if (missing.length === 0) continue;
        seen.add(match.line);
        findings.push(uploadFinding(this, entry.path, match.line, match.snippet, missing));
      }
      if (!isPython) continue;
      const reportedDefs = new Set(findings.filter((f) => f.filePath === entry.path).map((f) => pythonUploadDefLine(entry, f.lineStart)));
      for (const upload of fastapiUploads(entry)) {
        if (seen.has(upload.line) || reportedDefs.has(upload.defLine) || upload.inMemory) continue;
        const missing: string[] = [];
        if (!upload.facts.typeChecked) missing.push('allowed file types');
        if (!upload.facts.sizeChecked) missing.push('a size limit');
        if (missing.length === 0) continue;
        seen.add(upload.line);
        const snippet = (entry.content.split('\n')[upload.line - 1] ?? '').trim();
        findings.push(uploadFinding(this, entry.path, upload.line, snippet, missing));
      }
    }
    return findings;
  },
};

function uploadFinding(rule: ScanRule, filePath: string, line: number, snippet: string, missing: string[]): Finding {
  return makeFinding({
    ruleId: rule.id,
    title: rule.title,
    severity: missing.length === 2 ? 'high' : 'medium',
    confidence: 'medium',
    filePath,
    lineStart: line,
    evidence: `${snippet} (missing: ${missing.join(', ')})`,
    userExplanation:
      `This upload handler is missing ${missing.join(' and ')}. Attackers can upload huge files to exhaust your storage, or dangerous file types (like scripts) that later get executed. Restrict which file types are allowed and cap the size.`,
    technicalExplanation:
      `${filePath}:${line} configures file uploads without ${missing.join(' / ')}. Add a fileFilter validating MIME type/extension against an allowlist, set limits.fileSize, and store outside the web root with generated filenames.`,
    fixHint:
      'Add a fileFilter that allowlists expected MIME types/extensions, set limits: { fileSize }, generate random stored filenames, and store uploads outside the web/served directory (or in object storage).',
    category: rule.category,
  });
}
