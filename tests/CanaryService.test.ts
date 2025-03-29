import { CanaryService } from '../src/canary/CanaryService';

describe('CanaryService', () => {
  const tokenName = 'TEST_TOKEN';
  const jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const genericToken = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
  const shortToken = 'ABC123';
  
  test('should not modify tokens when disabled', () => {
    const canaryService = new CanaryService(false);
    
    // JWT token
    const jwtResult = canaryService.embedCanary(jwtToken, tokenName);
    expect(jwtResult).toBe(jwtToken);
    
    // Generic token
    const genericResult = canaryService.embedCanary(genericToken, tokenName);
    expect(genericResult).toBe(genericToken);
    
    // Short token
    const shortResult = canaryService.embedCanary(shortToken, tokenName);
    expect(shortResult).toBe(shortToken);
  });
  
  test('should embed canary in JWT token', () => {
    const canaryService = new CanaryService(true);
    
    // Embed canary
    const result = canaryService.embedCanary(jwtToken, tokenName);
    
    // Verify token is modified
    expect(result).not.toBe(jwtToken);
    
    // Verify structure is maintained
    const parts = result.split('.');
    expect(parts.length).toBe(3);
    
    // Verify header and signature are unchanged
    expect(parts[0]).toBe(jwtToken.split('.')[0]);
    expect(parts[2]).toBe(jwtToken.split('.')[2]);
    
    // Verify payload is modified
    expect(parts[1]).not.toBe(jwtToken.split('.')[1]);
    
    // Verify we can extract the canary
    const canaryTokenName = canaryService.detectCanary(result);
    expect(canaryTokenName).toBe(tokenName);
  });
  
  test('should embed canary in generic token', () => {
    const canaryService = new CanaryService(true);
    
    // Embed canary
    const result = canaryService.embedCanary(genericToken, tokenName);
    
    // Verify token is modified
    expect(result).not.toBe(genericToken);
    
    // Verify length is maintained (subtle modification)
    expect(result.length).toBe(genericToken.length);
    
    // Verify token is mostly unchanged (small modification)
    let diffCount = 0;
    for (let i = 0; i < genericToken.length; i++) {
      if (genericToken[i] !== result[i]) {
        diffCount++;
      }
    }
    expect(diffCount).toBeLessThan(3); // Only minor changes
  });
  
  test('should not modify short tokens', () => {
    const canaryService = new CanaryService(true);
    
    // Embed canary in short token
    const result = canaryService.embedCanary(shortToken, tokenName);
    
    // Should not modify tokens that are too short
    expect(result).toBe(shortToken);
  });
  
  test('should handle invalid JWT tokens gracefully', () => {
    const canaryService = new CanaryService(true);
    const invalidJwt = 'header.invalid payload.signature';
    
    // Should not throw and return original token
    const result = canaryService.embedCanary(invalidJwt, tokenName);
    expect(result).toBe(invalidJwt);
  });
  
  test('should not detect canary when disabled', () => {
    const canaryService = new CanaryService(false);
    
    // Create a canary-embedded token with a separate service
    const enabledService = new CanaryService(true);
    const token = enabledService.embedCanary(jwtToken, tokenName);
    
    // Should not detect canary when disabled
    const detected = canaryService.detectCanary(token);
    expect(detected).toBeNull();
  });
  
  test('should not detect canary in unmodified tokens', () => {
    const canaryService = new CanaryService(true);
    
    // Check unmodified tokens
    const jwtDetected = canaryService.detectCanary(jwtToken);
    const genericDetected = canaryService.detectCanary(genericToken);
    
    expect(jwtDetected).toBeNull();
    expect(genericDetected).toBeNull();
  });
  
  test('should handle invalid JWT tokens in detection', () => {
    const canaryService = new CanaryService(true);
    const invalidJwt = 'header.invalid payload.signature';
    
    // Should not throw and return null
    const detected = canaryService.detectCanary(invalidJwt);
    expect(detected).toBeNull();
  });
});
