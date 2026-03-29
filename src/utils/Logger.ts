/**
 * Log levels
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Simple logger utility
 */
export class Logger {
  private static readonly sensitiveKeys = new Set([
    'token',
    'accesstoken',
    'refreshtoken',
    'secret',
    'secretkey',
    'clientsecret',
    'password',
    'authorization',
    'cookie',
    'setcookie',
    'apikey',
    'accesskey',
    'secretaccesskey',
    'credential',
    'credentials',
    'privatekey'
  ]);

  constructor(private level: LogLevel = 'info') {}

  public debug(message: string, meta?: Record<string, unknown>): void {
    if (this.shouldLog('debug')) {
      console.debug(this.format('DEBUG', message, meta));
    }
  }

  public info(message: string, meta?: Record<string, unknown>): void {
    if (this.shouldLog('info')) {
      console.info(this.format('INFO', message, meta));
    }
  }

  public warn(message: string, meta?: Record<string, unknown>): void {
    if (this.shouldLog('warn')) {
      console.warn(this.format('WARN', message, meta));
    }
  }

  public error(message: string, meta?: Record<string, unknown>): void {
    if (this.shouldLog('error')) {
      console.error(this.format('ERROR', message, meta));
    }
  }

  private shouldLog(level: LogLevel): boolean {
    const levels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
    return levels.indexOf(level) >= levels.indexOf(this.level);
  }

  private format(level: string, message: string, meta?: Record<string, unknown>): string {
    const timestamp = new Date().toISOString();
    const metaStr = meta ? ` ${JSON.stringify(this.sanitizeValue(meta))}` : '';
    return `[${timestamp}] ${level}: ${message}${metaStr}`;
  }

  private sanitizeValue(value: unknown, visited: WeakSet<object> = new WeakSet()): unknown {
    if (value instanceof Error) {
      return {
        name: value.name,
        message: value.message
      };
    }

    if (value instanceof Date) {
      return value.toISOString();
    }

    if (Array.isArray(value)) {
      return value.map(entry => this.sanitizeValue(entry, visited));
    }

    if (value && typeof value === 'object') {
      if (visited.has(value)) {
        return '[Circular]';
      }

      visited.add(value);
      const sanitized: Record<string, unknown> = {};

      for (const [key, entry] of Object.entries(value)) {
        sanitized[key] = this.isSensitiveKey(key)
          ? '[REDACTED]'
          : this.sanitizeValue(entry, visited);
      }

      visited.delete(value);
      return sanitized;
    }

    return value;
  }

  private isSensitiveKey(key: string): boolean {
    const normalizedKey = key.replace(/[^a-z0-9]/gi, '').toLowerCase();
    return Logger.sensitiveKeys.has(normalizedKey);
  }
}
