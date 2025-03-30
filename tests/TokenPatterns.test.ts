import { TokenPatterns } from '../src/scanners/TokenPatterns';

describe('TokenPatterns', () => {
  let patterns: TokenPatterns;

  beforeEach(() => {
    patterns = new TokenPatterns();
  });

  describe('constructor', () => {
    it('should initialize with default values', () => {
      expect(patterns.name).toBe('default');
      expect(patterns.description).toBe('Default pattern for common tokens, social media profiles, serialized data, and metadata');
      expect(patterns.entropyThreshold).toBe(3.5);
      expect(patterns.severity).toBe('high');
      expect(patterns.regex).toBeInstanceOf(RegExp);
    });
  });

  describe('getAllPatterns', () => {
    it('should return all patterns', () => {
      const allPatterns = patterns.getAllPatterns();
      expect(allPatterns).toBeDefined();
      expect(typeof allPatterns).toBe('object');
      expect(Object.keys(allPatterns).length).toBeGreaterThan(0);
    });

    it('should include AWS patterns', () => {
      const allPatterns = patterns.getAllPatterns();
      expect(allPatterns.aws_access_key).toBeDefined();
      expect(allPatterns.aws_secret_key).toBeDefined();
      expect(allPatterns.aws_extended_key).toBeDefined();
    });

    it('should include GitHub patterns', () => {
      const allPatterns = patterns.getAllPatterns();
      expect(allPatterns.github_token).toBeDefined();
      expect(allPatterns.github_oauth).toBeDefined();
    });

    it('should include domain patterns', () => {
      const allPatterns = patterns.getAllPatterns();
      expect(allPatterns.email_domain).toBeDefined();
      expect(allPatterns.cloudfront_domain).toBeDefined();
      expect(allPatterns.aws_domain).toBeDefined();
    });

    it('should include social media patterns', () => {
      const allPatterns = patterns.getAllPatterns();
      expect(allPatterns.social_media_profile).toBeDefined();
    });

    it('should include serialized data patterns', () => {
      const allPatterns = patterns.getAllPatterns();
      expect(allPatterns.serialized_data).toBeDefined();
    });
  });

  describe('getPattern', () => {
    it('should return specific pattern by type', () => {
      expect(patterns.getPattern('aws_access_key')).toBe('(AKIA[0-9A-Z]{16})');
      expect(patterns.getPattern('github_token')).toBe('((ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36})');
    });

    it('should return null for non-existent pattern', () => {
      expect(patterns.getPattern('non_existent_pattern')).toBeNull();
    });
  });

  describe('addPattern', () => {
    it('should add new pattern', () => {
      patterns.addPattern('custom_pattern', '([a-z]{10})');
      expect(patterns.getPattern('custom_pattern')).toBe('([a-z]{10})');
    });

    it('should override existing pattern', () => {
      const newPattern = '([0-9]{20})';
      patterns.addPattern('aws_access_key', newPattern);
      expect(patterns.getPattern('aws_access_key')).toBe(newPattern);
    });
  });

  describe('regex matching', () => {
    it('should match AWS access key', () => {
      const testKey = 'AKIAXXXXXXXXXXXXXXXX';
      expect(testKey.match(patterns.regex)).toBeTruthy();
    });

    it('should match GitHub token', () => {
      const testToken = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      expect(testToken.match(patterns.regex)).toBeTruthy();
    });

    it('should match JWT token', () => {
      const testJWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      expect(testJWT.match(patterns.regex)).toBeTruthy();
    });

    it('should match social media profile URL', () => {
      const testUrls = [
        'https://www.facebook.com/username',
        'https://twitter.com/username',
        'https://www.linkedin.com/in/username'
      ];
      testUrls.forEach(url => {
        expect(url.match(patterns.regex)).toBeTruthy();
      });
    });

    it('should match serialized data', () => {
      const testData = [
        'a:3:{',
        'O:8:',
        'AAEAAAD/////AAAAA',
        'TypeObject',
        '$type',
        'application/x-java-serialized-object'
      ];
      testData.forEach(data => {
        expect(data.match(patterns.regex)).toBeTruthy();
      });
    });

    it('should match open graph meta tags', () => {
      const testTag = '<meta property="og:title" content="Test Title">';
      expect(testTag.match(patterns.regex)).toBeTruthy();
    });
  });
}); 