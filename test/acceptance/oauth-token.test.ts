import * as tap from 'tap';
import * as cli from '../../src/cli/commands';
import { chdirWorkspaces, getWorkspaceJSON } from './workspace-helper';
import { fakeServer } from './fake-server';

const { test } = tap;

const port = (process.env.PORT = process.env.SNYK_PORT = '12345');
const BASE_API = '/api/v1';
process.env.SNYK_API = `http://localhost:${port}${BASE_API}`;
process.env.SNYK_HOST = `http://localhost:${port}`;
process.env.LOG_LEVEL = '0';
const apiKey = '123456789';
let oldkey;
let oldendpoint;
const server = fakeServer(BASE_API, apiKey);

const noVulnsResult = getWorkspaceJSON(
  'fail-on',
  'no-vulns',
  'vulns-result.json',
);

test('setup', async (t) => {
  let key = await cli.config('get', 'api');
  oldkey = key;
  t.pass(`existing user config captured: ${oldkey}`);

  key = await cli.config('get', 'endpoint');
  oldendpoint = key;
  t.pass(`existing user endpoint captured: ${oldendpoint}`);

  await new Promise((resolve) => {
    server.listen(port, resolve);
  });
  t.pass('started demo server');
  t.end();
});

test('prime config', async (t) => {
  await cli.config('unset', 'endpoint');
  t.pass('endpoint removed');

  await cli.config('unset', 'api');
  t.pass('api key removed');

  process.env.SNYK_OAUTH_TOKEN = 'oauth-jwt-token';
  t.pass('oauth token set');

  t.end();
});

test('`snyk test` with docker flag - docker token and no api key', async (t) => {
  try {
    server.setNextResponse(noVulnsResult);
    chdirWorkspaces('fail-on');
    await cli.test('no-vulns', {
      json: true,
    });
    const req = server.popRequest();
    t.match(
      req.headers.authorization,
      'bearer oauth-jwt-token',
      'sends correct authorization header',
    );
    t.equal(req.method, 'POST', 'makes POST request');
  } catch (err) {
    if (err.code === 401) {
      t.fail('did not send correct authorization header');
      t.end();
    }
    t.fail(`did not expect exception to be thrown ${err}`);
  }
});

test('teardown', async (t) => {
  delete process.env.SNYK_API;
  delete process.env.SNYK_HOST;
  delete process.env.SNYK_PORT;
  delete process.env.SNYK_OAUTH_TOKEN;
  t.notOk(process.env.SNYK_PORT, 'fake env values cleared');

  await new Promise((resolve) => {
    server.close(resolve);
  });
  t.pass('server shutdown');

  if (!oldkey) {
    await cli.config('unset', 'api');
  } else {
    await cli.config('set', `api=${oldkey}`);
  }

  if (oldendpoint) {
    await cli.config('set', `endpoint=${oldendpoint}`);
    t.pass('user endpoint restored');
  } else {
    t.pass('no endpoint');
  }
  t.pass('user config restored');
  t.end();
});
