import * as debugLib from 'debug';
import * as pathLib from 'path';
const sortBy = require('lodash.sortby');
const groupBy = require('lodash.groupby');

import {
  EntityToFix,
  FixChangesSummary,
  FixOptions,
  RemediationChanges,
  Workspace,
} from '../../../../types';
import { PluginFixResponse } from '../../../types';
import { updateDependencies } from './update-dependencies';
import { MissingRemediationDataError } from '../../../../lib/errors/missing-remediation-data';
import { MissingFileNameError } from '../../../../lib/errors/missing-file-name';
import { partitionByFixable } from './is-supported';
import { NoFixesCouldBeAppliedError } from '../../../../lib/errors/no-fixes-applied';
import { extractProvenance } from './extract-version-provenance';
import {
  ParsedRequirements,
  parseRequirementsFile,
} from './update-dependencies/requirements-file-parser';

const debug = debugLib('snyk-fix:python:requirements.txt');

export async function pipRequirementsTxt(
  entities: EntityToFix[],
  options: FixOptions,
): Promise<PluginFixResponse> {
  debug(`Preparing to fix ${entities.length} Python requirements.txt projects`);
  const handlerResult: PluginFixResponse = {
    succeeded: [],
    failed: [],
    skipped: [],
  };

  const { fixable, skipped: notFixable } = await partitionByFixable(entities);
  handlerResult.skipped.push(...notFixable);

  const ordered = sortByDirectory(fixable);
  const fixedFilesCache: string[] = [];
  for (const dir of Object.keys(ordered)) {
    debug(`Fixing entities in directory ${dir}`);
    const entitiesPerDirectory = ordered[dir].map((e) => e.entity);
    const { failed, succeeded, skipped, fixedFiles } = await fixAll(
      entitiesPerDirectory,
      options,
      fixedFilesCache,
    );
    fixedFilesCache.push(...fixedFiles);
    handlerResult.succeeded.push(...succeeded);
    handlerResult.failed.push(...failed);
    handlerResult.skipped.push(...skipped);
  }
  return handlerResult;
}

export function getRequiredData(
  entity: EntityToFix,
): {
  remediation: RemediationChanges;
  targetFile: string;
  workspace: Workspace;
} {
  const { remediation } = entity.testResult;
  if (!remediation) {
    throw new MissingRemediationDataError();
  }
  const { targetFile } = entity.scanResult.identity;
  if (!targetFile) {
    throw new MissingFileNameError();
  }
  const { workspace } = entity;
  if (!workspace) {
    throw new NoFixesCouldBeAppliedError();
  }
  return { targetFile, remediation, workspace };
}

async function fixAll(
  entities: EntityToFix[],
  options: FixOptions,
  fixedCache: string[],
): Promise<PluginFixResponse & { fixedFiles: string[] }> {
  const handlerResult: PluginFixResponse = {
    succeeded: [],
    failed: [],
    skipped: [],
  };
  for (const entity of entities) {
    const targetFile = entity.scanResult.identity.targetFile!;
    try {
      const { dir, base } = pathLib.parse(targetFile);
      // parse & join again to support correct separator
      if (fixedCache.includes(pathLib.join(dir, base))) {
        handlerResult.succeeded.push({
          original: entity,
          changes: [{ success: true, userMessage: 'Previously fixed' }],
        });
        continue;
      }
      const { changes, fixedFiles } = await applyAllFixes(entity, options);
      if (!changes.length) {
        debug('Manifest has not changed!');
        throw new NoFixesCouldBeAppliedError();
      }
      fixedCache.push(...fixedFiles);
      handlerResult.succeeded.push({ original: entity, changes });
    } catch (e) {
      debug(`Failed to fix ${targetFile}.\nERROR: ${e}`);
      handlerResult.failed.push({ original: entity, error: e });
    }
  }
  return { ...handlerResult, fixedFiles: [] };
}
// TODO: optionally verify the deps install
export async function fixIndividualRequirementsTxt(
  workspace: Workspace,
  dir: string,
  entryFileName: string,
  fileName: string,
  remediation: RemediationChanges,
  parsedRequirements: ParsedRequirements,
  options: FixOptions,
  directUpgradesOnly: boolean,
): Promise<{ changes: FixChangesSummary[]; appliedRemediation: string[] }> {
  const fullFilePath = pathLib.join(dir, fileName);
  const { updatedManifest, changes, appliedRemediation } = updateDependencies(
    parsedRequirements,
    remediation.pin,
    directUpgradesOnly,
    pathLib.join(dir, entryFileName) !== fullFilePath ? fileName : undefined,
  );

  if (!changes.length) {
    return { changes, appliedRemediation };
  }

  if (!options.dryRun) {
    debug('Writing changes to file');
    await workspace.writeFile(pathLib.join(dir, fileName), updatedManifest);
  } else {
    debug('Skipping writing changes to file in --dry-run mode');
  }

  return { changes, appliedRemediation };
}

export async function applyAllFixes(
  entity: EntityToFix,
  options: FixOptions,
): Promise<{ changes: FixChangesSummary[]; fixedFiles: string[] }> {
  const { remediation, targetFile: entryFileName, workspace } = getRequiredData(
    entity,
  );
  const fixedFiles: string[] = [];
  const { dir, base } = pathLib.parse(entryFileName);
  const provenance = await extractProvenance(workspace, dir, base);
  const upgradeChanges: FixChangesSummary[] = [];
  const appliedUpgradeRemediation: string[] = [];
  /* Apply all upgrades first across all files that are included */
  for (const fileName of Object.keys(provenance)) {
    const skipApplyingPins = true;
    const { changes, appliedRemediation } = await fixIndividualRequirementsTxt(
      workspace,
      dir,
      base,
      fileName,
      remediation,
      provenance[fileName],
      options,
      skipApplyingPins,
    );
    appliedUpgradeRemediation.push(...appliedRemediation);
    upgradeChanges.push(...changes);
    fixedFiles.push(pathLib.join(dir, fileName));
  }

  /* Apply all left over remediation as pins in the entry targetFile */
  const requirementsTxt = await workspace.readFile(entryFileName);

  const toPin: RemediationChanges = filterOutAppliedUpgrades(
    remediation,
    appliedUpgradeRemediation,
  );
  const directUpgradesOnly = false;
  const { changes: pinnedChanges } = await fixIndividualRequirementsTxt(
    workspace,
    dir,
    base,
    base,
    toPin,
    parseRequirementsFile(requirementsTxt),
    options,
    directUpgradesOnly,
  );

  return { changes: [...upgradeChanges, ...pinnedChanges], fixedFiles };
}

function filterOutAppliedUpgrades(
  remediation: RemediationChanges,
  appliedRemediation: string[],
): RemediationChanges {
  const pinRemediation: RemediationChanges = {
    ...remediation,
    pin: {}, // delete the pin remediation so we can collect un-applied remediation
  };
  const pins = remediation.pin;
  const lowerCasedAppliedRemediation = appliedRemediation.map((i) =>
    i.toLowerCase(),
  );
  for (const pkgAtVersion of Object.keys(pins)) {
    if (!lowerCasedAppliedRemediation.includes(pkgAtVersion.toLowerCase())) {
      pinRemediation.pin[pkgAtVersion] = pins[pkgAtVersion];
    }
  }
  return pinRemediation;
}

function sortByDirectory(
  entities: EntityToFix[],
): {
  [dir: string]: Array<{
    entity: EntityToFix;
    dir: string;
    base: string;
    ext: string;
    root: string;
    name: string;
  }>;
} {
  const mapped = entities.map((e) => ({
    entity: e,
    ...pathLib.parse(e.scanResult.identity.targetFile!),
  }));

  const sorted = sortBy(mapped, 'dir');
  return groupBy(sorted, 'dir');
}
