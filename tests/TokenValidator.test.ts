import { TokenValidator } from '../src/validation/TokenValidator';

describe('TokenValidator', () => {
  const validator = new TokenValidator();

  const buildJwt = (claims: Record<string, unknown>) => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
    const payload = Buffer.from(JSON.stringify(claims)).toString('base64');
    return `${header}.${payload}.signature`;
  };

  it('validates a strong token successfully', () => {
    const token = 'Abcd1234!@#$EfGH';
    const result = validator.validate(token);

    expect(result.isValid).toBe(true);
    expect(result.metadata.entropy).toBeGreaterThan(3);
    expect(result.issues).toHaveLength(0);
  });

  it('fails tokens that are too short or low entropy', () => {
    const token = 'aaaa';
    const result = validator.validate(token, { minLength: 10, minEntropy: 3 });

    expect(result.isValid).toBe(false);
    expect(result.issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining('below minimum required length'),
        expect.stringContaining('below minimum required')
      ])
    );
  });

  it('validates JWT structure and captures metadata', () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    const jwt = buildJwt({ sub: '123', exp: future });

    const result = validator.validate(jwt);

    expect(result.isValid).toBe(true);
    expect(result.metadata.type).toBe('JWT');
    expect(result.metadata.format?.header.alg).toBe('HS256');
    expect(result.metadata.format?.payload.sub).toBe('123');
  });

  it('captures missing required character types', () => {
    const token = '1234567890123456';
    const result = validator.validate(token, { requiredCharTypes: ['uppercase', 'lowercase', 'numbers'] });

    expect(result.isValid).toBe(false);
    expect(result.issues).toEqual(
      expect.arrayContaining([
        'Token is missing required character type: uppercase',
        'Token is missing required character type: lowercase'
      ])
    );
  });

  it('honors custom validation hooks', () => {
    const token = 'Abcd1234!@#$EfGH';
    const result = validator.validate(token, { customValidation: () => false });

    expect(result.isValid).toBe(false);
    expect(result.issues).toContain('Token failed custom validation');
  });
});
