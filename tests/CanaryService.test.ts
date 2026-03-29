import { sign, verify } from 'jsonwebtoken';
import { CanaryService } from '../src/canary/CanaryService';

describe('CanaryService', () => {
  let canaryService: CanaryService;
  
  beforeEach(() => {
    canaryService = new CanaryService(true);
  });

  test('should embed and detect canary in a long hex token', () => {
    const tokenName = 'test_token';
    const originalToken = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    
    const tokenWithCanary = canaryService.embedCanary(originalToken, tokenName);
    expect(tokenWithCanary).not.toBe(originalToken);
    
    const detectedTokenName = canaryService.detectCanary(tokenWithCanary);
    expect(detectedTokenName).toBe(tokenName);
  });

  test('should not modify JWT tokens because canary embedding would invalidate the signature', () => {
    const secret = 'jwt-secret';
    const originalToken = sign({ sub: 'user-123' }, secret, {
      issuer: 'token-guardian',
      audience: 'default',
      expiresIn: 3600
    });

    const tokenWithCanary = canaryService.embedCanary(originalToken, 'jwt-token');

    expect(tokenWithCanary).toBe(originalToken);
    expect(canaryService.detectCanary(tokenWithCanary)).toBeNull();
    expect(() => verify(tokenWithCanary, secret, {
      issuer: 'token-guardian',
      audience: 'default'
    })).not.toThrow();
  });

  test('should not modify short tokens', () => {
    const shortToken = '123';
    const tokenWithCanary = canaryService.embedCanary(shortToken, 'short-token');
    expect(tokenWithCanary).toBe(shortToken);
  });

  test('should not detect canary in regular token', () => {
    const regularToken = 'REGULAR_TOKEN_123';
    const detectedTokenName = canaryService.detectCanary(regularToken);
    expect(detectedTokenName).toBeNull();
  });

  test('should not detect canaries when disabled', () => {
    const disabledService = new CanaryService(false);
    const originalToken = 'API_KEY_12345';
    const tokenName = 'test-api-key';
    
    const tokenWithCanary = disabledService.embedCanary(originalToken, tokenName);
    expect(tokenWithCanary).toBe(originalToken);
    
    const detectedTokenName = disabledService.detectCanary(tokenWithCanary);
    expect(detectedTokenName).toBeNull();
  });
});
