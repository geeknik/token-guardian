import { PatternScanner } from '../src/scanners/PatternScanner';

describe('PatternScanner', () => {
  const scanner = new PatternScanner();
  
  test('should detect AWS access key', () => {
    const input = 'My AWS access key is AKIAIOSFODNN7EXAMPLE';
    const result = scanner.scan(input);
    
    expect(result.found).toBe(true);
    expect(result.matches.length).toBeGreaterThan(0);
    expect(result.matches[0].type).toBe('aws_access_key');
    expect(result.matches[0].value).toBe('AKIAIOSFODNN7EXAMPLE');
  });
  
  test('should detect GitHub token', () => {
    const input = 'My GitHub token is ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9';
    const result = scanner.scan(input);
    
    expect(result.found).toBe(true);
    expect(result.matches.length).toBeGreaterThan(0);
    expect(result.matches[0].type).toBe('github_token');
    expect(result.matches[0].value).toBe('ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9');
  });
  
  test('should detect JWT token', () => {
    const input = 'My JWT is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const result = scanner.scan(input);
    
    expect(result.found).toBe(true);
    expect(result.matches.length).toBeGreaterThan(0);
    expect(result.matches[0].type).toBe('jwt_token');
  });
  
  test('should detect multiple tokens in the same input', () => {
    const input = `
      AWS key: AKIAIOSFODNN7EXAMPLE
      GitHub token: ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9
    `;
    const result = scanner.scan(input);
    
    expect(result.found).toBe(true);
    expect(result.matches.length).toBe(2);
  });
  
  test('should not find any tokens in clean input', () => {
    const input = 'This is a clean string with no secrets';
    const result = scanner.scan(input);
    
    expect(result.found).toBe(false);
    expect(result.matches.length).toBe(0);
  });
  
  test('should calculate entropy correctly', () => {
    const lowEntropyInput = 'aaaaaaaaaa'; // Low entropy (all same characters)
    const highEntropyInput = 'aB1@cD2#eF'; // High entropy (varied characters)
    
    const lowResult = scanner.scan(lowEntropyInput);
    const highResult = scanner.scan(highEntropyInput);
    
    expect(lowResult.entropy).toBeLessThan(highResult.entropy);
  });
});
