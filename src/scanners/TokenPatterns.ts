import { TokenPattern } from '../interfaces/TokenPattern';

/**
 * Collection of regex patterns for detecting various types of tokens and secrets
 */
export class TokenPatterns implements TokenPattern {
  public name: string;
  public regex: RegExp;
  public description: string;
  public entropyThreshold: number;
  public severity: 'low' | 'medium' | 'high';

  private patterns: Record<string, string>;

  constructor() {
    this.name = 'default';
    this.regex = /(?:AKIA[0-9A-Z]{16})|(?:ghp_[a-zA-Z0-9]{36})|(?:eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+)/;
    this.description = 'Default pattern for common tokens';
    this.entropyThreshold = 3.5;
    this.severity = 'high';

    this.patterns = {
      // AWS
      'aws_access_key': '(AKIA[0-9A-Z]{16})',
      'aws_secret_key': '([0-9a-zA-Z/+]{40})',
      'aws_extended_key': '((A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})',
      'aws_api_gateway': '([0-9a-z]+.execute-api.[0-9a-z.-_]+.amazonaws.com)',
      'aws_arn': '(arn:aws:[a-z0-9-]+:[a-z]{2}-[a-z]+-[0-9]+:[0-9]+:.+)',
      'aws_appsync_key': '(da2-[a-z0-9]{26})',
      'aws_cloudfront': '([0-9a-z.-_]+.cloudfront.net)',
      'aws_ec2': '(ec2-[0-9a-z.-_]+.compute(-1)?.amazonaws.com)',
      'aws_internal': '([0-9a-z.-_]+.compute(-1)?.internal)',
      'aws_elb': '([0-9a-z.-_]+.elb.amazonaws.com)',
      'aws_elasticache': '([0-9a-z.-_]+.cache.amazonaws.com)',
      'aws_mws': '(mzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
      'aws_mws_alt': '(amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
      'aws_rds': '([0-9a-z.-_]+.rds.amazonaws.com)',
      'aws_s3_url': '(s3://[0-9a-z.-_/]+)',
      'aws_s3_endpoint': '([a-zA-Z0-9.-_]+.s3.[a-zA-Z0-9.-_]+.amazonaws.com)',
      
      // GitHub
      'github_token': '((ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36})',
      'github_oauth': '(gho_[0-9a-zA-Z]{36})',
      
      // API Keys
      'stripe_api_key': '((sk|pk)_(test|live)_[0-9a-zA-Z]{24,34})',
      'google_api_key': '(AIza[0-9A-Za-z\\-_]{35})',
      'twilio_api_key': '(SK[0-9a-fA-F]{32})',
      'sendgrid_api_key': '(SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43})',
      'abstract_api_key': '([0-9a-z]{32})',
      'abuseipdb_api_key': '([a-z0-9]{80})',
      'accuweather_api_key': '([a-z0-9A-Z\\%]{35})',
      'adobe_api_key': '([a-z0-9]{32})',
      'adobe_client_secret': '([a-zA-Z0-9.]{12})',
      'adzuna_api_key': '([a-z0-9]{8}|[a-z0-9]{32})',
      'aero_api_key': '([0-9]{1,})',
      'aero_secret': '([a-zA-Z0-9^!]{20})',
      'agora_api_key': '([a-z0-9]{32})',
      'airbrake_api_key': '([0-9]{6}|[a-zA-Z-0-9]{32}|[a-zA-Z-0-9]{40})',
      'airship_api_key': '([0-9Aa-zA-Z]{91})',
      'airvisual_api_key': '([a-z0-9-]{36})',
      'aletheia_api_key': '([A-Z0-9]{32})',
      'algolia_api_key': '([A-Z0-9]{10}|[a-zA-Z0-9]{32})',
      'alienvault_api_key': '([a-z0-9]{64})',
      'allsports_api_key': '([0-9a-z]{64})',
      'amadeus_api_key': '([0-9A-Za-z]{32}|[0-9A-Za-z]{16})',
      'ambee_api_key': '([0-9a-f]{64})',
      'amplitude_api_key': '([a-f0-9]{32})',
      'apacta_api_key': '([a-z0-9-]{36})',
      'api2cart_api_key': '([0-9a-f]{32})',
      'apideck_api_key': '([a-z0-9A-Z]{40})',
      'apiflash_api_key': '([a-z0-9]{32}|[a-zA-Z0-9\\S]{21,30})',
      
      // JWT Tokens
      'jwt_token': '(eyJ[a-zA-Z0-9_-]{2,}\\.[a-zA-Z0-9_-]{2,}\\.[a-zA-Z0-9_-]{2,})',
      
      // Private Keys
      'ssh_private_key': '(-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----)',
      'pgp_private_key': '(-----BEGIN PGP PRIVATE KEY BLOCK-----)',
      
      // Database
      'mongodb_conn_string': '(mongodb(\\+srv)?://[^\\s<>]+)',
      'postgresql_conn_string': '(postgres(ql)?://[^\\s<>]+)',
      'mysql_conn_string': '(mysql://[^\\s<>]+)',
      
      // Other
      'password_in_url': '(https?://[^:@\\s]+:[^:@\\s]*@[^:\\s]+)',
      'potential_cryptographic_key': '([0-9a-fA-F]{32,})',
      'uuid': '([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})',
      'admin_secret': '(admin).+(secret|token|key|password).+',
      'generic_api_key': '(aio_[a-zA-Z0-9]{28})',
      'stripe_live_key': '(sk_live_[a-z0-9A-Z-]{93})',
      'apifonica_key': '([0-9a-z]{11}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})',
      'apify_key': '(apify_api_[a-zA-Z-0-9]{36})',
      'apimatic_key': '([a-z0-9-\\S]{8,32})',
      'apimatic_email': '([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})',
      'apiscience_key': '([a-bA-Z0-9\\S]{22})',
      'apollo_key': '([a-zA-Z0-9]{22})',
      'appcues_key': '([0-9]{5}|[a-z0-9-]{36})'
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
