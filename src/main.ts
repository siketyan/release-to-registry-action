import { readFile } from 'fs/promises';

import { getInput, getMultilineInput, setFailed, setOutput } from '@actions/core';
import { render } from 'mustache/mustache.js';
import fetch from 'node-fetch-commonjs';
import { Octokit } from 'octokit';
import { createHash } from 'crypto';

type Input = {
  tag: string,
  hash: string,
  owner: string,
  repo: string,
  assets: string[],
  path: string,
  message: string,
  template: string,
  token: string,
  targetOwner?: string,
  targetRepo?: string,
  branch?: string,
  author?: string,
  committer?: string,
  prTitle?: string,
  prBody?: string,
};

const computeHash = async (algorithm: string, url: string): Promise<string> => {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(await response.text());
  }

  const hash = createHash(algorithm);
  hash.update(new Uint8Array(await response.arrayBuffer()));

  return hash.digest('hex');
};

const emptyAsUndefined = (str: string): string | undefined => str === '' ? undefined : str;

const parseAuthorOrCommitter = (str?: string): { name: string, email: string } | undefined => {
  if (str === undefined) {
    return undefined;
  }

  const match = /^(?<name>.+) <(?<email>.+)>$/.exec(str);
  if (match === null) {
    throw new Error(`Author or committer '${str}' does not match the format 'Forename Surname <foo@example.com>'.`)
  }

  return {
    name: match['name'],
    email: match['email'],
  };
};

const run = async (
  { tag, owner, repo, path, assets, message, template, token, hash, targetOwner, targetRepo, branch, author, committer, prTitle, prBody }: Input,
  octokit: Octokit,
) => {
  const release = await octokit.rest.repos.getReleaseByTag({
    owner,
    repo,
    tag,
  });

  console.log('Found a release', release.data);

  const assetDefs = Object.fromEntries(
    assets.map((def): [string, string] => {
      const [left, right] = def.split('=', 2);
      return [right, left];
    }),
  );

  console.log('Asset definitions', assetDefs);

  const rendered = render((await readFile(template)).toString(), {
    tag,
    tag_without_v: tag.startsWith('v') ? tag.substring(1) : tag,
    release: release.data,
    assets: Object.fromEntries(await Promise.all(release.data.assets.map(async asset => [assetDefs[asset.name], {
      ...asset,
      hash: hash && await computeHash(hash, asset.url),
    }])))
  });

  console.log('Rendered', rendered);

  owner = targetOwner ?? owner;
  repo = targetRepo ?? repo;

  const commit = await octokit.rest.repos.createOrUpdateFileContents({
    owner,
    repo,
    path,
    branch,
    author: parseAuthorOrCommitter(author),
    committer: parseAuthorOrCommitter(committer),
    message,
    content: Buffer.from(rendered).toString('base64'),
  });

  setOutput('commit', commit.data.commit.sha);

  if (branch === undefined) {
    console.log('Default branch was specified, so no pull request was created.');

    return;
  }

  const repository = await octokit.rest.repos.get({
    owner,
    repo,
  })

  const pullRequest = await octokit.rest.pulls.create({
    owner: targetOwner,
    repo: targetRepo,
    head: branch,
    base: repository.data.default_branch,
    title: prTitle ?? message,
    body: prBody,
  });

  console.log('Created a pull request', pullRequest.data);

  setOutput('pull_request', pullRequest.data.number);
};

(async () => {
  try {
    const input = {
      tag: getInput('tag'),
      owner: getInput('owner'),
      repo: getInput('repo'),
      path: getInput('path'),
      assets: getMultilineInput('assets'),
      message: getInput('message'),
      template: getInput('template'),
      token: getInput('token'),
      hash: emptyAsUndefined('hash'),
      targetOwner: emptyAsUndefined(getInput('targetOwner')),
      targetRepo: emptyAsUndefined(getInput('targetRepo')),
      branch: emptyAsUndefined(getInput('branch')),
      author: emptyAsUndefined(getInput('author')),
      committer: emptyAsUndefined(getInput('committer')),
      prTitle: emptyAsUndefined(getInput('prTitle')),
      prBody: emptyAsUndefined(getInput('prBody')),
    };

    const octokit = new Octokit({
      auth: input.token,
    });

    await run(input, octokit);
  } catch (error) {
    setFailed(error);
  }
})()
  .then()
;
