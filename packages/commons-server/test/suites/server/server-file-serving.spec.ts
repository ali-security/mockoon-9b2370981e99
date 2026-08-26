import { Environment } from '@mockoon/commons';
import { expect } from 'chai';
import { promises as fs } from 'fs';
import { get } from 'http';
import { resolve as pathResolve } from 'path';
import { MockoonServer } from '../../../src';

type HttpResponse = { status: number; body: string };

const port = 3005;
const environmentDirectory = pathResolve('./test/data/environments');

async function getEnvironment(name: string): Promise<Environment> {
  const environmentJson = await fs.readFile(
    `./test/data/environments/${name}-env.json`,
    'utf-8'
  );

  return JSON.parse(environmentJson) as Environment;
}

function httpGet(path: string): Promise<HttpResponse> {
  return new Promise<HttpResponse>((promiseResolve, promiseReject) => {
    get(`http://localhost:${port}${path}`, (response) => {
      let body = '';

      response.setEncoding('utf-8');
      response.on('data', (chunk) => {
        body += chunk;
      });
      response.on('end', () => {
        promiseResolve({ status: response.statusCode ?? 0, body });
      });
    }).on('error', promiseReject);
  });
}

describe('Server file serving path traversal', () => {
  const serverErrors: string[] = [];
  let environment: Environment;
  let server: MockoonServer;

  before(async () => {
    environment = await getEnvironment('file-serving');
    // built at runtime to stay cross-platform (native path separators)
    environment.routes[2].responses[0].filePath = pathResolve(
      environmentDirectory,
      "{{queryParam 'filename'}}"
    );

    server = new MockoonServer(environment, { environmentDirectory });
    // a blocked path emits a server error, unhandled ones would be thrown
    server.on('error', (errorCode, originalError) => {
      serverErrors.push(`${errorCode}: ${originalError?.message}`);
    });

    await new Promise<void>((promiseResolve) => {
      server.once('started', () => promiseResolve());
      server.start();
    });
  });

  after(() => {
    server.stop();
  });

  it('should serve a static path escaping the environment directory', async () => {
    const { status, body } = await httpGet('/static-escape');

    expect(status).to.equal(200);
    expect(body).to.equal('plainTest');
  });

  it('should serve a templated relative path staying in the environment directory', async () => {
    const { status, body } = await httpGet('/relative?filename=inside.data');

    expect(status).to.equal(200);
    expect(body).to.equal('insideEnvDir');
  });

  it('should block a templated relative path escaping the environment directory', async () => {
    const { body } = await httpGet('/relative?filename=../plain.data');

    expect(body).to.contain(
      'Access to relative path outside of the environment base directory'
    );
    expect(body).to.not.contain('plainTest');
  });

  it('should serve a templated absolute path staying in its static base', async () => {
    const { status, body } = await httpGet('/absolute?filename=inside.data');

    expect(status).to.equal(200);
    expect(body).to.equal('insideEnvDir');
  });

  it('should block a templated absolute path escaping its static base', async () => {
    const { body } = await httpGet('/absolute?filename=../plain.data');

    expect(body).to.contain(
      'Access to absolute path outside of the original static base directory'
    );
    expect(body).to.not.contain('plainTest');
  });

  it('should serve a templated url param path inside the static folder', async () => {
    const { status, body } = await httpGet('/static/sub.data');

    expect(status).to.equal(200);
    expect(body).to.equal('subDirFile');
  });

  it('should block the url encoded traversal reported in the advisory', async () => {
    const traversal = await httpGet('/static/%2F..%2F..%2Fplain.data');

    expect(traversal.body).to.contain(
      'Access to relative path outside of the environment base directory'
    );
    expect(traversal.body).to.not.contain('plainTest');

    const passwd = await httpGet(
      '/static/%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd'
    );

    expect(passwd.body).to.contain(
      'Access to relative path outside of the environment base directory'
    );
    expect(passwd.body).to.not.contain('root:');

    // the error is also surfaced to the consumers (CLI logs, desktop app)
    expect(serverErrors.join('\n')).to.contain(
      'Access to relative path outside of the environment base directory'
    );
  });
});
