import { CanaryService } from '../src/canary/CanaryService';

describe('CanaryService', () => {
  let canaryService: CanaryService;
  
  beforeEach(() => {
    canaryService = new CanaryService(true);
  });

  test('should embed and detect canary in token', () => {
    const tokenName = 'test_token';
    const originalToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    
    const tokenWithCanary = canaryService.embedCanary(originalToken, tokenName);
    expect(tokenWithCanary).not.toBe(originalToken);
    
    const detectedTokenName = canaryService.detectCanary(tokenWithCanary);
    expect(detectedTokenName).toBe(tokenName);
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
