var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/main.ts
var import_promises = require("fs/promises");
var import_core = require("../node_modules/@actions/core/lib/core.js");
var import_mustache = require("../node_modules/mustache/mustache.js");
var import_node_fetch_commonjs = __toESM(require("../node_modules/node-fetch-commonjs/index.js"));
var import_octokit = require("../node_modules/octokit/dist-node/index.js");
var import_crypto = require("crypto");
var computeHash = async (algorithm, url) => {
  const response = await (0, import_node_fetch_commonjs.default)(url);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  const hash = (0, import_crypto.createHash)(algorithm);
  hash.update(new Uint8Array(await response.arrayBuffer()));
  return hash.digest("hex");
};
var emptyAsUndefined = (str) => str === "" ? void 0 : str;
var parseAuthorOrCommitter = (str) => {
  if (str === void 0) {
    return void 0;
  }
  const match = /^(?<name>.+) <(?<email>.+)>$/.exec(str);
  if (match === null) {
    throw new Error(`Author or committer '${str}' does not match the format 'Forename Surname <foo@example.com>'.`);
  }
  return {
    name: match["name"],
    email: match["email"]
  };
};
var run = async ({ tag, owner, repo, path, assets, message, template, token, hash, targetOwner, targetRepo, branch, author, committer, prTitle, prBody }, octokit) => {
  const release = await octokit.rest.repos.getReleaseByTag({
    owner,
    repo,
    tag
  });
  console.log("Found a release", release.data);
  const assetDefs = Object.fromEntries(
    assets.map((def) => {
      const [left, right] = def.split("=", 2);
      return [right, left];
    })
  );
  console.log("Asset definitions", assetDefs);
  const rendered = (0, import_mustache.render)((await (0, import_promises.readFile)(template)).toString(), {
    tag,
    tag_without_v: tag.startsWith("v") ? tag.substring(1) : tag,
    release: release.data,
    assets: Object.fromEntries(await Promise.all(release.data.assets.map(async (asset) => [assetDefs[asset.name], {
      ...asset,
      hash: hash && await computeHash(hash, asset.url)
    }])))
  });
  console.log("Rendered", rendered);
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
    content: Buffer.from(rendered).toString("base64")
  });
  (0, import_core.setOutput)("commit", commit.data.commit.sha);
  if (branch === void 0) {
    console.log("Default branch was specified, so no pull request was created.");
    return;
  }
  const repository = await octokit.rest.repos.get({
    owner,
    repo
  });
  const pullRequest = await octokit.rest.pulls.create({
    owner: targetOwner,
    repo: targetRepo,
    head: branch,
    base: repository.data.default_branch,
    title: prTitle ?? message,
    body: prBody
  });
  console.log("Created a pull request", pullRequest.data);
  (0, import_core.setOutput)("pull_request", pullRequest.data.number);
};
(async () => {
  try {
    const input = {
      tag: (0, import_core.getInput)("tag"),
      owner: (0, import_core.getInput)("owner"),
      repo: (0, import_core.getInput)("repo"),
      path: (0, import_core.getInput)("path"),
      assets: (0, import_core.getMultilineInput)("assets"),
      message: (0, import_core.getInput)("message"),
      template: (0, import_core.getInput)("template"),
      token: (0, import_core.getInput)("token"),
      hash: emptyAsUndefined("hash"),
      targetOwner: emptyAsUndefined((0, import_core.getInput)("targetOwner")),
      targetRepo: emptyAsUndefined((0, import_core.getInput)("targetRepo")),
      branch: emptyAsUndefined((0, import_core.getInput)("branch")),
      author: emptyAsUndefined((0, import_core.getInput)("author")),
      committer: emptyAsUndefined((0, import_core.getInput)("committer")),
      prTitle: emptyAsUndefined((0, import_core.getInput)("prTitle")),
      prBody: emptyAsUndefined((0, import_core.getInput)("prBody"))
    };
    const octokit = new import_octokit.Octokit({
      auth: input.token
    });
    await run(input, octokit);
  } catch (error) {
    (0, import_core.setFailed)(error);
  }
})().then();
