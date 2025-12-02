import { sign, verify } from 'jsonwebtoken';
import { DefaultRotator } from '../src/rotation/services/DefaultRotator';

describe('DefaultRotator', () => {
  const secretKey = 'rotator-secret';

  it('rotates a valid token and returns a new JWT', async () => {
    const currentToken = sign({ sub: 'user-123' }, secretKey, {
      issuer: 'token-guardian',
      audience: 'default',
      expiresIn: 3600
    });

    const rotator = new DefaultRotator({ secretKey });
    const result = await rotator.rotateToken(currentToken);

    expect(result.success).toBe(true);
    expect(result.newToken).toBeDefined();
    expect(result.newExpiry).toBeInstanceOf(Date);
    expect(result.metadata).toMatchObject({ issuer: 'token-guardian', audience: 'default' });

    const payload = verify(result.newToken as string, secretKey, {
      issuer: 'token-guardian',
      audience: 'default'
    }) as { sub?: string };
    expect(payload.sub).toBe('user-123');
  });

  it('returns a failed result when validation fails', async () => {
    const rotator = new DefaultRotator({ secretKey });
    const result = await rotator.rotateToken('not-a-jwt');

    expect(result.success).toBe(false);
    expect(result.message).toBe('Invalid token');
    expect(result.newToken).toBeUndefined();
    expect(result.newExpiry).toBeNull();
  });
});
