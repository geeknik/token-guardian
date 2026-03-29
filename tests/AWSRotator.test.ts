import { AWSRotator } from '../src/rotation/services/AWSRotator';

describe('AWSRotator', () => {
  test('creates canonical requests from mixed-case headers without throwing', () => {
    const rotator = new AWSRotator() as unknown as {
      createCanonicalRequest: (request: {
        method: string;
        path: string;
        region: string;
        service: string;
        headers: Record<string, string>;
        params: Record<string, string>;
      }) => string;
    };

    const canonicalRequest = rotator.createCanonicalRequest({
      method: 'GET',
      path: '/',
      region: 'us-east-1',
      service: 'iam',
      headers: {
        Host: 'iam.amazonaws.com',
        'X-Amz-Date': '20260329T000000Z'
      },
      params: {
        Action: 'ListAccessKeys',
        Version: '2010-05-08'
      }
    });

    expect(canonicalRequest).toContain('host:iam.amazonaws.com');
    expect(canonicalRequest).toContain('x-amz-date:20260329T000000Z');
    expect(canonicalRequest).toContain('\nhost;x-amz-date\n');
  });

  test('adds an authorization header when signing requests with mixed-case headers', () => {
    const rotator = new AWSRotator() as unknown as {
      signAwsRequest: (request: {
        method: string;
        path: string;
        region: string;
        service: string;
        headers: Record<string, string>;
        params: Record<string, string>;
        host: string;
      }, accessKey: string, secretKey: string) => { headers: Record<string, string> };
    };

    const signedRequest = rotator.signAwsRequest({
      host: 'iam.amazonaws.com',
      method: 'GET',
      path: '/',
      region: 'us-east-1',
      service: 'iam',
      headers: {
        Host: 'iam.amazonaws.com',
        'X-Amz-Date': '20260329T000000Z'
      },
      params: {
        Action: 'ListAccessKeys',
        Version: '2010-05-08'
      }
    }, 'AKIAEXAMPLEKEY12345', 'secretExampleKey');

    expect(signedRequest.headers.Authorization).toContain('AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEKEY12345/');
    expect(signedRequest.headers.Authorization).toContain('SignedHeaders=host;x-amz-date');
  });

  test('parses access keys only from the expected IAM result block', () => {
    const rotator = new AWSRotator() as unknown as {
      parseAccessKeyListResponse: (xml: string) => string[];
    };

    const keys = rotator.parseAccessKeyListResponse(`
      <ListAccessKeysResponse>
        <ListAccessKeysResult>
          <AccessKeyMetadata>
            <member><AccessKeyId>AKIAFIRSTKEY123456</AccessKeyId></member>
            <member><AccessKeyId>AKIASECONDKEY12345</AccessKeyId></member>
          </AccessKeyMetadata>
        </ListAccessKeysResult>
        <ResponseMetadata>
          <RequestId>abc</RequestId>
        </ResponseMetadata>
      </ListAccessKeysResponse>
    `);

    expect(keys).toEqual(['AKIAFIRSTKEY123456', 'AKIASECONDKEY12345']);
  });

  test('rejects malformed create-access-key XML responses', () => {
    const rotator = new AWSRotator() as unknown as {
      parseCreateAccessKeyResponse: (xml: string) => { accessKeyId: string; secretAccessKey: string };
    };

    expect(() => rotator.parseCreateAccessKeyResponse(`
      <CreateAccessKeyResponse>
        <ResponseMetadata>
          <AccessKeyId>AKIASHOULDNOTMATCH123</AccessKeyId>
        </ResponseMetadata>
      </CreateAccessKeyResponse>
    `)).toThrow('expected CreateAccessKeyResult block');
  });
});
