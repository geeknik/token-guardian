import { TokenRotator } from '../src/rotation/TokenRotator';
import { RotationResult } from '../src/interfaces/RotationResult';

describe('TokenRotator', () => {
  const originalSecretKey = process.env.TOKEN_GUARDIAN_SECRET_KEY;

  afterEach(() => {
    if (originalSecretKey === undefined) {
      delete process.env.TOKEN_GUARDIAN_SECRET_KEY;
    } else {
      process.env.TOKEN_GUARDIAN_SECRET_KEY = originalSecretKey;
    }
  });

  it('delegates rotation to the registered rotator', async () => {
    const rotator = new TokenRotator();

    const mockResult: RotationResult = {
      success: true,
      message: 'rotated',
      newToken: 'new-token',
      newExpiry: null
    };

    const mockStrategy = {
      rotateToken: jest.fn().mockResolvedValue(mockResult)
    };

    rotator.registerRotator('default', mockStrategy);

    const result = await rotator.rotateToken('old-token');

    expect(mockStrategy.rotateToken).toHaveBeenCalledWith('old-token', undefined);
    expect(result).toEqual(mockResult);
  });

  it('routes rotation to the named rotator with the token identifier', async () => {
    const rotator = new TokenRotator();

    const mockResult: RotationResult = {
      success: true,
      message: 'rotated',
      newToken: 'service-token',
      newExpiry: null
    };

    const mockStrategy = {
      rotateToken: jest.fn().mockResolvedValue(mockResult)
    };

    rotator.registerRotator('custom-service', mockStrategy);

    const result = await rotator.rotateToken('old-token', 'custom-service', 'API_KEY');

    expect(mockStrategy.rotateToken).toHaveBeenCalledWith('old-token', 'API_KEY');
    expect(result).toEqual(mockResult);
  });

  it('returns a specific rotator by name', () => {
    const rotator = new TokenRotator();
    const mockStrategy = { rotateToken: jest.fn() };

    rotator.registerRotator('custom', mockStrategy);

    expect(rotator.getRotator('custom')).toBe(mockStrategy);
  });

  it('fails closed when the default JWT rotator secret is not configured', () => {
    delete process.env.TOKEN_GUARDIAN_SECRET_KEY;

    const rotator = new TokenRotator();

    expect(() => rotator.getRotator('default')).toThrow('Rotator not found: default');
  });
});
