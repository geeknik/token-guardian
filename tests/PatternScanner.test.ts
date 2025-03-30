import { PatternScanner } from '../src/scanners/PatternScanner';
import { TokenPattern } from '../src/interfaces/TokenPattern';

const testPatterns: TokenPattern[] = [
  {
    name: 'AWS Access Key',
    regex: /AKIA[0-9A-Z]{16}/,
    description: 'AWS Access Key ID',
    entropyThreshold: 3.5,
    severity: 'high'
  },
  {
    name: 'GitHub Token',
    regex: /ghp_[a-zA-Z0-9]{36}/,
    description: 'GitHub Personal Access Token',
    entropyThreshold: 4.0,
    severity: 'high'
  },
  {
    name: 'JWT Token',
    regex: /eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+/,
    description: 'JSON Web Token',
    entropyThreshold: 3.0,
    severity: 'medium',
    validate: (token: string) => {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return false;
      }
      try {
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        return (
          typeof header === 'object' &&
          header !== null &&
          typeof payload === 'object' &&
          payload !== null &&
          typeof header.alg === 'string' &&
          typeof header.typ === 'string'
        );
      } catch {
        return false;
      }
    }
  }
];

describe('PatternScanner', () => {
  let _scanner: PatternScanner;
  
  beforeEach(() => {
    _scanner = new PatternScanner(testPatterns);
  });

  test('detects AWS access key', () => {
    const scanner = new PatternScanner([testPatterns[0]]);
    const input = 'AKIAIOSFODNN7EXAMPLE';
    const result = scanner.scan(input, 'test.txt');
    
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('aws_access_key');
    expect(result[0].value).toBe('AKIAIOSFODNN7EXAMPLE');
  });

  test('detects GitHub token', () => {
    const scanner = new PatternScanner([testPatterns[1]]);
    const input = 'ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r';
    const result = scanner.scan(input, 'test.txt');
    
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('github_token');
    expect(result[0].value).toBe('ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r');
  });

  test('detects JWT token', () => {
    const scanner = new PatternScanner([testPatterns[2]]);
    const input = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const result = scanner.scan(input, 'test.txt');
    
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('jwt_token');
  });

  test('detects multiple tokens', () => {
    const scanner = new PatternScanner([testPatterns[0], testPatterns[1]]);
    const input = `
      AWS Key: AKIAIOSFODNN7EXAMPLE
      GitHub Token: ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r
    `;
    const result = scanner.scan(input, 'test.txt');
    
    expect(result.length).toBe(2);
  });

  test('does not detect non-matching strings', () => {
    const scanner = new PatternScanner([testPatterns[0], testPatterns[1]]);
    const input = 'This is a normal string with no tokens';
    const result = scanner.scan(input, 'test.txt');
    
    expect(result.length).toBe(0);
  });

  test('considers entropy in detection', () => {
    const scanner = new PatternScanner([testPatterns[0]]);
    const lowEntropyInput = 'AKIAAAAAAAAAAAAAAAAA'; // Low entropy
    const highEntropyInput = 'AKIAIOSFODNN7EXAMPLE'; // High entropy
    
    const lowResult = scanner.scan(lowEntropyInput, 'test.txt');
    const highResult = scanner.scan(highEntropyInput, 'test.txt');
    
    expect(lowResult.length).toBe(0);  // Should not detect low entropy token
    expect(highResult.length).toBe(1);  // Should detect high entropy token
  });
});
