import { Logger } from '../utils/Logger';

/**
 * Token validation result
 */
export interface ValidationResult {
  /** Whether the token is valid */
  isValid: boolean;
  /** Validation issues found */
  issues: string[];
  /** Token metadata */
  metadata: {
    /** Token type if detected */
    type?: string;
    /** Token entropy score */
    entropy: number;
    /** Token length */
    length: number;
    /** Token format details */
    format?: Record<string, unknown>;
  };
}

/**
 * Token validation options
 */
export interface ValidationOptions {
  /** Minimum required entropy */
  minEntropy?: number;
  /** Minimum required length */
  minLength?: number;
  /** Maximum allowed length */
  maxLength?: number;
  /** Required character types */
  requiredCharTypes?: ('uppercase' | 'lowercase' | 'numbers' | 'special')[];
  /** Whether to validate as JWT */
  validateJWT?: boolean;
  /** Custom validation function */
  customValidation?: (token: string) => boolean;
}

/**
 * Service for validating tokens
 */
export class TokenValidator {
  private logger: Logger;
  private defaultOptions: ValidationOptions = {
    minEntropy: 3.0,
    minLength: 16,
    maxLength: 1024,
    requiredCharTypes: ['uppercase', 'lowercase', 'numbers'],
    validateJWT: true
  };

  constructor(logger?: Logger) {
    this.logger = logger || new Logger('info');
  }

  /**
   * Calculate Shannon entropy of a string
   * @param str String to analyze
   * @returns Entropy value
   */
  private calculateEntropy(str: string): number {
    const len = str.length;
    const frequencies = new Map<string, number>();

    // Calculate character frequencies
    for (const char of str) {
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }

    // Calculate entropy using Shannon's formula
    return Array.from(frequencies.values()).reduce((entropy, freq) => {
      const probability = freq / len;
      return entropy - probability * Math.log2(probability);
    }, 0);
  }

  /**
   * Check which character types are present in a string
   * @param str String to check
   * @returns Object indicating presence of each character type
   */
  private checkCharacterTypes(str: string): Record<string, boolean> {
    return {
      uppercase: /[A-Z]/.test(str),
      lowercase: /[a-z]/.test(str),
      numbers: /[0-9]/.test(str),
      special: /[^A-Za-z0-9]/.test(str)
    };
  }

  /**
   * Validate a JWT token
   * @param token Token to validate
   * @returns Validation result
   */
  private validateJWT(token: string): { isValid: boolean; issues: string[]; format?: Record<string, unknown> } {
    const issues: string[] = [];
    let format: Record<string, unknown> = {};

    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        issues.push('Invalid JWT format: must have 3 parts');
        return { isValid: false, issues };
      }

      // Decode and validate header
      const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
      if (!header.alg) {
        issues.push('Invalid JWT: missing algorithm in header');
      }
      if (!header.typ) {
        issues.push('Invalid JWT: missing type in header');
      }

      // Decode and validate payload
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      format = {
        header,
        payload,
        signatureLength: parts[2].length
      };

      // Basic payload validation
      if (payload.exp && typeof payload.exp === 'number') {
        const expiry = new Date(payload.exp * 1000);
        if (expiry < new Date()) {
          issues.push('JWT is expired');
        }
      }

      return {
        isValid: issues.length === 0,
        issues,
        format
      };
    } catch (error) {
      issues.push(`JWT parsing error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return { isValid: false, issues };
    }
  }

  /**
   * Validate a token
   * @param token Token to validate
   * @param options Validation options
   * @returns Validation result
   */
  public validate(token: string, options: ValidationOptions = {}): ValidationResult {
    const opts = { ...this.defaultOptions, ...options };
    const issues: string[] = [];
    const metadata: ValidationResult['metadata'] = {
      length: token.length,
      entropy: this.calculateEntropy(token)
    };

    // Check length
    if (opts.minLength && token.length < opts.minLength) {
      issues.push(`Token length (${token.length}) is below minimum required length (${opts.minLength})`);
    }
    if (opts.maxLength && token.length > opts.maxLength) {
      issues.push(`Token length (${token.length}) exceeds maximum allowed length (${opts.maxLength})`);
    }

    // Check entropy
    if (opts.minEntropy && metadata.entropy < opts.minEntropy) {
      issues.push(`Token entropy (${metadata.entropy.toFixed(2)}) is below minimum required (${opts.minEntropy})`);
    }

    // Check character types
    if (opts.requiredCharTypes && opts.requiredCharTypes.length > 0) {
      const charTypes = this.checkCharacterTypes(token);
      for (const required of opts.requiredCharTypes) {
        if (!charTypes[required]) {
          issues.push(`Token is missing required character type: ${required}`);
        }
      }
    }

    // Check if it's a JWT
    if (opts.validateJWT && token.split('.').length === 3) {
      metadata.type = 'JWT';
      const jwtValidation = this.validateJWT(token);
      issues.push(...jwtValidation.issues);
      metadata.format = jwtValidation.format;
    }

    // Run custom validation if provided
    if (opts.customValidation) {
      try {
        if (!opts.customValidation(token)) {
          issues.push('Token failed custom validation');
        }
      } catch (error) {
        issues.push(`Custom validation error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    // Try to detect token type if not already determined
    if (!metadata.type) {
      if (/^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/.test(token)) {
        metadata.type = 'Base64-URL';
      } else if (/^[A-Fa-f0-9]+$/.test(token)) {
        metadata.type = 'Hex';
      } else if (/^[A-Za-z0-9+/=]+$/.test(token)) {
        metadata.type = 'Base64';
      }
    }

    // Log validation result
    if (issues.length > 0) {
      this.logger.warn('Token validation failed', { issues, metadata });
    } else {
      this.logger.debug('Token validation passed', { metadata });
    }

    return {
      isValid: issues.length === 0,
      issues,
      metadata
    };
  }
} 
