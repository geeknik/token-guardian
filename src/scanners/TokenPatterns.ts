/**
 * Collection of regex patterns for detecting various types of tokens and secrets
 */
export class TokenPatterns {
  private patterns: Record<string, string>;

  constructor() {
    this.patterns = {
      // AWS
      'aws_access_key': 'AKIA[0-9A-Z]{16}',
      'aws_secret_key': '[0-9a-zA-Z/+]{40}',
      
      // GitHub
      'github_token': '(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}',
      'github_oauth': 'gho_[0-9a-zA-Z]{36}',
      
      // API Keys
      'stripe_api_key': '(sk|pk)_(test|live)_[0-9a-zA-Z]{24,34}',
      'google_api_key': 'AIza[0-9A-Za-z\\-_]{35}',
      'twilio_api_key': 'SK[0-9a-fA-F]{32}',
      'sendgrid_api_key': 'SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}',
      
      // JWT Tokens
      'jwt_token': 'eyJ[a-zA-Z0-9_-]{5,}\\.[a-zA-Z0-9_-]{5,}\\.[a-zA-Z0-9_-]{5,}',
      
      // Private Keys
      'ssh_private_key': '-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
      'pgp_private_key': '-----BEGIN PGP PRIVATE KEY BLOCK-----',
      
      // Database
      'mongodb_conn_string': 'mongodb(\\+srv)?://[^\\s<>]+',
      'postgresql_conn_string': 'postgres(ql)?://[^\\s<>]+',
      'mysql_conn_string': 'mysql://[^\\s<>]+',
      
      // Other
      'password_in_url': '(https?://[^:@\\s]+:[^:@\\s]*@[^:\\s]+)',
      'potential_cryptographic_key': '[0-9a-fA-F]{32,}'
    };
  }

  /**
   * Gets all token patterns
   * @returns Object containing all patterns
   */
  public getAllPatterns(): Record<string, string> {
    return this.patterns;
  }

  /**
   * Gets a specific pattern by type
   * @param type The type of pattern to get
   * @returns The regex pattern string or null if not found
   */
  public getPattern(type: string): string | null {
    return this.patterns[type] || null;
  }

  /**
   * Adds a new pattern to the collection
   * @param type The type/name of the pattern
   * @param pattern The regex pattern string
   */
  public addPattern(type: string, pattern: string): void {
    this.patterns[type] = pattern;
  }
}
