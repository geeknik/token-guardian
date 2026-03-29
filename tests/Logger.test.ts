import { Logger } from '../src/utils/Logger';

describe('Logger', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('redacts sensitive metadata keys before logging', () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const logger = new Logger('error');

    logger.error('request failed', {
      token: 'top-secret-token',
      nested: {
        authorization: 'Bearer super-secret'
      },
      tokenName: 'PUBLIC_LABEL'
    });

    const output = consoleErrorSpy.mock.calls[0][0] as string;

    expect(output).toContain('"token":"[REDACTED]"');
    expect(output).toContain('"authorization":"[REDACTED]"');
    expect(output).toContain('"tokenName":"PUBLIC_LABEL"');
    expect(output).not.toContain('top-secret-token');
    expect(output).not.toContain('super-secret');
  });

  test('serializes Error metadata without stack traces', () => {
    const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const logger = new Logger('warn');
    const error = new Error('boom');
    error.stack = 'sensitive stack';

    logger.warn('operation failed', { error });

    const output = consoleWarnSpy.mock.calls[0][0] as string;

    expect(output).toContain('"name":"Error"');
    expect(output).toContain('"message":"boom"');
    expect(output).not.toContain('sensitive stack');
  });
});
