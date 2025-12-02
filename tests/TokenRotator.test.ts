import { TokenRotator } from '../src/rotation/TokenRotator';
import { RotationResult } from '../src/interfaces/RotationResult';

describe('TokenRotator', () => {
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

    expect(mockStrategy.rotateToken).toHaveBeenCalledWith('old-token');
    expect(result).toEqual(mockResult);
  });

  it('returns a specific rotator by name', () => {
    const rotator = new TokenRotator();
    const mockStrategy = { rotateToken: jest.fn() };

    rotator.registerRotator('custom', mockStrategy);

    expect(rotator.getRotator('custom')).toBe(mockStrategy);
  });
});
