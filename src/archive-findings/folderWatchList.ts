import {
  UNEXPECTED_CATEGORY_ORDER,
  type ArchiveWatchListCarry,
  type ReportedPathList,
} from '../shared/archiveObservations.js';
import { createArchiveNameCollector } from '../upload/archiveNameScan.js';
import type { ReportedPath } from '../upload/reportedPath.js';

export interface FolderWatchList {
  observe(relativePath: string): void;
  carry(): ArchiveWatchListCarry;
}

export function folderWatchList(): FolderWatchList {
  const collector = createArchiveNameCollector();
  return {
    observe(relativePath: string): void {
      collector.observe({ path: relativePath, isDirectory: false, eligible: false });
    },
    carry(): ArchiveWatchListCarry {
      const names = collector.result();
      const whole = (entry: ReportedPath): ReportedPath =>
        names.rootPrefix === undefined || entry.truncated
          ? entry
          : { path: `${names.rootPrefix}/${entry.path}`, truncated: false };
      return {
        source: 'folder',
        groups: UNEXPECTED_CATEGORY_ORDER.map((category) => ({
          category,
          count: names.unexpectedFiles[category].count,
          sample: pathList(names.unexpectedFiles[category].sample.map(whole)),
        })),
      };
    },
  };
}

function pathList(paths: readonly ReportedPath[]): ReportedPathList {
  const list: ReportedPathList = { paths: [], shortened: [] };
  for (const entry of paths) {
    if (entry.truncated) list.shortened.push(list.paths.length);
    list.paths.push(entry.path);
  }
  return list;
}
