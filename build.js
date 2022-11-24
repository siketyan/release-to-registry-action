const path = require('path');
const nodeModule = require('module');

const nodeRequire = nodeModule.createRequire(import.meta.url);

/**
 * @param {Array<string>} specifiers
 * @returns {import('esbuild').Plugin}
 */
function resolveCjsPlugin(specifiers) {
  const filter = new RegExp(specifiers.join('|'));
  return {
    name: 'resolveCjs',
    setup(build) {
      build.onResolve({ filter }, (args) => {
        return {
          path: path.join(nodeRequire.resolve(args.path)),
        };
      });
    },
  };
}

require('esbuild')
  .build({
    entryPoints: [__dirname + '/src/main.ts'],
    bundle: true,
    outfile: __dirname + '/dist/index.js',
    platform: 'node',
    external: ['./node_modules/*'],
    plugins: [resolveCjsPlugin(['mustache'])],
  })
  .catch(() => process.exit(1))
;
