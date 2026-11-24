import * as core from '@actions/core';
import * as fs from 'fs';
import { spawnCli } from './analyzer.js';
import { installAnalyzerCli } from './cli.js';
import { commentBody, commentWarning, pullRequestNumber, restCommentApi, upsertComment } from './comment.js';
import { runMode, type Deps } from './gate.js';
import { parseInputs, parsePrComment } from './inputs.js';

function readEventPayload(): unknown {
  const file = process.env.GITHUB_EVENT_PATH;
  if (!file) {
    return undefined;
  }
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return undefined;
  }
}

/** The comment on the pull request of the event, or undefined when there is none to post. */
function prCommenter(enabled: boolean): Deps['prComment'] {
  const payload = readEventPayload();
  const prNumber = pullRequestNumber(process.env.GITHUB_EVENT_NAME, payload);
  if (!enabled || prNumber === undefined) {
    return undefined;
  }
  const token = core.getInput('github-token');
  const repository = process.env.GITHUB_REPOSITORY;
  if (!token || !repository) {
    core.warning('No github-token, so the gate does not comment on the pull request');
    return undefined;
  }
  core.setSecret(token);
  const api = restCommentApi({
    apiUrl: process.env.GITHUB_API_URL || 'https://api.github.com',
    repository,
    token,
  });
  const { GITHUB_SERVER_URL, GITHUB_RUN_ID } = process.env;
  const sha = (payload as { pull_request?: { head?: { sha?: string } } } | undefined)?.pull_request?.head
    ?.sha;
  const run =
    GITHUB_SERVER_URL && GITHUB_RUN_ID
      ? `[run ${GITHUB_RUN_ID}](${GITHUB_SERVER_URL}/${repository}/actions/runs/${GITHUB_RUN_ID})`
      : 'the latest run';
  const footer = `<sub>From ${run}${sha ? ` on ${sha.slice(0, 7)}` : ''}. Updated on each run.</sub>`;
  return async (key, body) => {
    try {
      const done = await upsertComment(api, prNumber, key, commentBody(key, body, footer));
      core.info(`Comment on pull request #${prNumber} ${done}`);
    } catch (err) {
      core.warning(commentWarning(err));
    }
  };
}

async function main() {
  try {
    const inputs = parseInputs(core.getInput);
    core.setSecret(inputs.apiKey);
    const prComment = prCommenter(parsePrComment(core.getInput));

    const analyzerPath = installAnalyzerCli(inputs.cliVersion, inputs.apiKey, inputs.apiUrl, core.info);
    const deps: Deps = {
      cli: spawnCli(analyzerPath, core.info),
      log: core,
      setOutput: core.setOutput,
      writeSummary: async (markdown) => {
        if (process.env.GITHUB_STEP_SUMMARY) {
          await core.summary.addRaw(markdown).write();
        }
      },
      outDir: process.cwd(),
      now: Date.now,
      setFailed: core.setFailed,
      ...(prComment ? { prComment } : {}),
    };

    await runMode(inputs, deps);
  } catch (error) {
    core.setFailed(error instanceof Error ? error.message : String(error));
  }
}

main();
