import axios, { AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import { ServiceRotator } from '../ServiceRotator';
import { RotationResult } from '../../interfaces/RotationResult';
import { createLogger, Logger, transports, format } from 'winston';

/**
 * GitHub OAuth2 configuration interface
 */
export interface GitHubOAuth2Config {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string[];
  tokenEndpoint?: string;
  authorizationEndpoint?: string;
  userEndpoint?: string;
  tokenInfoEndpoint?: string;
}

/**
 * GitHub API Token information
 */
export interface GitHubToken {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  expiresAt?: Date;
  tokenType: string;
  scope: string[];
}

/**
 * Rate limit information from GitHub API
 */
export interface RateLimitInfo {
  limit: number;
  remaining: number;
  reset: number; // Unix timestamp
  used: number;
  resource: string;
}

/**
 * Retry configuration options
 */
export interface RetryOptions {
  maxRetries: number;
  initialDelayMs: number;
  maxDelayMs: number;
  backoffFactor: number;
  retryStatusCodes: number[];
}
/**
 * Rotator for GitHub tokens with OAuth2 support
 */
export class GitHubRotator implements ServiceRotator {
  private readonly apiBaseUrl: string = 'https://api.github.com';
  private readonly authBaseUrl: string = 'https://github.com';
  private readonly axiosInstance: AxiosInstance;
  private readonly logger: Logger;
  private readonly oauth2Config?: GitHubOAuth2Config;
  private readonly retryOptions: RetryOptions;
  private static readonly OAUTH_HEADERS = {
    Accept: 'application/json',
    'Content-Type': 'application/json'
  };
  private static readonly authHeader = (token: string) => ({
    Authorization: `token ${token}`
  });
  
  /**
   * Creates a new GitHubRotator instance
   * @param oauth2Config Optional OAuth2 configuration for OAuth flow
   * @param retryOptions Optional retry configuration
   * @param axiosConfig Optional Axios configuration
   */
  constructor(
    oauth2Config?: GitHubOAuth2Config,
    retryOptions?: Partial<RetryOptions>,
    axiosConfig?: AxiosRequestConfig
  ) {
    this.oauth2Config = oauth2Config;
    
    // Initialize retry options with defaults
    this.retryOptions = {
      maxRetries: retryOptions?.maxRetries ?? 3,
      initialDelayMs: retryOptions?.initialDelayMs ?? 1000,
      maxDelayMs: retryOptions?.maxDelayMs ?? 30000,
      backoffFactor: retryOptions?.backoffFactor ?? 2,
      retryStatusCodes: retryOptions?.retryStatusCodes ?? [429, 500, 502, 503, 504]
    };
    
    // Initialize axios instance with default config
    this.axiosInstance = axios.create({
      baseURL: this.apiBaseUrl,
      timeout: 10000,
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'TokenGuardian-Rotator'
      },
      ...axiosConfig
    });
    
    // Add response interceptor for rate limit handling
    this.axiosInstance.interceptors.response.use(
      (response) => {
        // Extract and store rate limit info for logging
        this.parseRateLimitHeaders(response);
        return response;
      },
      (error) => {
        if (this.isRateLimited(error)) {
          this.logger.warn('GitHub API rate limit exceeded', { 
            rateLimitReset: error.response?.headers['x-ratelimit-reset']
          });
        }
        return Promise.reject(error);
      }
    );
    
    // Initialize logger
    this.logger = createLogger({
      level: 'info',
      format: format.combine(
        format.timestamp(),
        format.json()
      ),
      defaultMeta: { service: 'github-rotator' },
      transports: [
        new transports.Console({
          format: format.combine(
            format.colorize(),
            format.simple()
          )
        })
      ]
    });
  }
  
  /**
   * Parses rate limit information from GitHub API response headers
   * @param response Axios response object
   * @returns Rate limit information or undefined if not present
   */
  private parseRateLimitHeaders(response: AxiosResponse): RateLimitInfo | undefined {
    const headers = response.headers;
    
    if (
      headers['x-ratelimit-limit'] &&
      headers['x-ratelimit-remaining'] &&
      headers['x-ratelimit-reset']
    ) {
      const rateLimitInfo: RateLimitInfo = {
        limit: parseInt(headers['x-ratelimit-limit'] as string, 10),
        remaining: parseInt(headers['x-ratelimit-remaining'] as string, 10),
        reset: parseInt(headers['x-ratelimit-reset'] as string, 10),
        used: parseInt(headers['x-ratelimit-used'] as string, 10) || 0,
        resource: headers['x-ratelimit-resource'] as string || 'core'
      };
      
      // Log if we're getting close to the limit (less than 10% remaining)
      if (rateLimitInfo.remaining < rateLimitInfo.limit * 0.1) {
        this.logger.warn('GitHub API rate limit getting low', { 
          remaining: rateLimitInfo.remaining,
          limit: rateLimitInfo.limit,
          resetAt: new Date(rateLimitInfo.reset * 1000).toISOString()
        });
      }
      
      return rateLimitInfo;
    }
    
    return undefined;
  }
  
  /**
   * Checks if an error is due to GitHub API rate limiting
   * @param error Axios error object
   * @returns True if rate limited, false otherwise
   */
  private isRateLimited(error: AxiosError): boolean {
    return !!(
      error.response &&
      error.response.status === 429 &&
      error.response.headers &&
      error.response.headers['x-ratelimit-remaining'] === '0'
    );
  }
  
  /**
   * Calculates backoff delay for retries using exponential backoff algorithm
   * @param retryCount Current retry count
   * @param error Error that triggered the retry
   * @returns Delay in milliseconds before next retry
   */
  private calculateBackoffDelay(retryCount: number, error?: AxiosError): number {
    let delay = this.retryOptions.initialDelayMs * Math.pow(this.retryOptions.backoffFactor, retryCount);
    
    // Add jitter to prevent thundering herd problem (±10%)
    const jitter = delay * 0.1 * (Math.random() * 2 - 1);
    delay += jitter;
    
    // If rate limited, use the reset time from headers if available
    if (error?.response?.headers && this.isRateLimited(error)) {
      const resetTime = parseInt(error.response.headers['x-ratelimit-reset'] as string, 10);
      if (!isNaN(resetTime)) {
        const resetDelayMs = (resetTime * 1000) - Date.now() + 1000; // Add 1 second buffer
        if (resetDelayMs > 0) {
          delay = Math.min(resetDelayMs, this.retryOptions.maxDelayMs);
        }
      }
    }
    
    return Math.min(delay, this.retryOptions.maxDelayMs);
  }
  
  /**
   * Makes an API request with automatic retry and backoff
   * @param config Axios request configuration
   * @returns Promise with axios response
   */
  private async makeRequestWithRetry<T = unknown>(
    config: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    let retryCount = 0;
    
    const executeRequest = async (): Promise<AxiosResponse<T>> => {
      try {
        return await this.axiosInstance.request<T>(config);
      } catch (error) {
        const axiosError = error as AxiosError;
        
        // Determine if we should retry
        const shouldRetry = 
          retryCount < this.retryOptions.maxRetries && 
          (
            this.isRateLimited(axiosError) || 
            (axiosError.response && this.retryOptions.retryStatusCodes.includes(axiosError.response.status))
          );
        
        if (shouldRetry) {
          retryCount++;
          const delay = this.calculateBackoffDelay(retryCount, axiosError);
          
          this.logger.info(`Retrying request (${retryCount}/${this.retryOptions.maxRetries})`, {
            delay,
            /* url: config.url, -- removed to avoid logging sensitive endpoint */,
            status: axiosError.response?.status,
            method: config.method
          });
          
          await new Promise(resolve => setTimeout(resolve, delay));
          return executeRequest();
        }
        
        // If we shouldn't retry, rethrow the error
        throw error;
      }
    };
    
    return executeRequest();
  }
  
  /**
   * Retrieves user info with the given token
   * @param token GitHub token to validate
   * @returns User information and scopes
   */
  private async getUserInfo(token: string): Promise<{ username: string; tokenScopes: string[] }> {
    try {
      const response = await this.makeRequestWithRetry<{ login: string }>({
        url: '/user',
        method: 'GET',
        headers: GitHubRotator.authHeader(token)
      });
      
      const scopeHeader = response.headers['x-oauth-scopes'] as string;
      const tokenScopes = scopeHeader ? scopeHeader.split(', ') : [];
      const username = response.data.login;
      
      return { username, tokenScopes };
    } catch (error) {
      const axiosError = error as AxiosError;
      if (axiosError.response?.status === 401) {
        throw new Error('Token is invalid or expired');
      }
      throw error;
    }
  }
  
  /**
   * Exchanges an authorization code for an OAuth2 token
   * @param code Authorization code from OAuth flow
   * @returns GitHub token information
   */
  public async exchangeCodeForToken(code: string): Promise<GitHubToken> {
    if (!this.oauth2Config) {
      throw new Error('OAuth2 configuration is required for this operation');
    }
    
    try {
      const tokenEndpoint = this.oauth2Config.tokenEndpoint || `${this.authBaseUrl}/login/oauth/access_token`;
      
      type OAuthTokenResponse = {
        access_token: string;
        refresh_token?: string;
        expires_in?: number;
        token_type?: string;
        scope?: string;
      };

      const response = await this.makeRequestWithRetry<OAuthTokenResponse>({
        url: tokenEndpoint,
        method: 'POST',
        headers: GitHubRotator.OAUTH_HEADERS,
        data: {
          client_id: this.oauth2Config.clientId,
          client_secret: this.oauth2Config.clientSecret,
          code,
          redirect_uri: this.oauth2Config.redirectUri
        }
      });
      
      const data = response.data;
      
      if (!data.access_token) {
        throw new Error('Failed to obtain access token');
      }
      
      // Calculate expiration date if expires_in is provided
      let expiresAt: Date | undefined;
      if (data.expires_in) {
        expiresAt = new Date();
        expiresAt.setSeconds(expiresAt.getSeconds() + data.expires_in);
      }
      
      const token: GitHubToken = {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresIn: data.expires_in,
        expiresAt,
        tokenType: data.token_type || 'bearer',
        scope: data.scope ? data.scope.split(',') : []
      };
      
      this.logger.info('Successfully exchanged code for token', {
        scopes: token.scope,
        expiresIn: token.expiresIn
      });
      
      return token;
    } catch (error) {
      this.logger.error('Failed to exchange code for token', { error });
      throw new Error(`OAuth2 token exchange failed: ${this.formatError(error)}`);
    }
  }
  
  /**
   * Refreshes an OAuth2 token using a refresh token
   * @param refreshToken Refresh token to use
   * @returns New GitHub token information
   */
  public async refreshOAuth2Token(refreshToken: string): Promise<GitHubToken> {
    if (!this.oauth2Config) {
      throw new Error('OAuth2 configuration is required for this operation');
    }
    
    try {
      const tokenEndpoint = this.oauth2Config.tokenEndpoint || `${this.authBaseUrl}/login/oauth/access_token`;
      
      type OAuthTokenResponse = {
        access_token: string;
        refresh_token?: string;
        expires_in?: number;
        token_type?: string;
        scope?: string;
      };

      const response = await this.makeRequestWithRetry<OAuthTokenResponse>({
        url: tokenEndpoint,
        method: 'POST',
        headers: GitHubRotator.OAUTH_HEADERS,
        data: {
          client_id: this.oauth2Config.clientId,
          client_secret: this.oauth2Config.clientSecret,
          refresh_token: refreshToken,
          grant_type: 'refresh_token'
        }
      });
      
      const data = response.data;
      
      if (!data.access_token) {
        throw new Error('Failed to refresh access token');
      }
      
      // Calculate expiration date if expires_in is provided
      let expiresAt: Date | undefined;
      if (data.expires_in) {
        expiresAt = new Date();
        expiresAt.setSeconds(expiresAt.getSeconds() + data.expires_in);
      }
      
      const token: GitHubToken = {
        accessToken: data.access_token,
        refreshToken: data.refresh_token || refreshToken, // Use new refresh token or keep old one
        expiresIn: data.expires_in,
        expiresAt,
        tokenType: data.token_type || 'bearer',
        scope: data.scope ? data.scope.split(',') : []
      };
      
      this.logger.info('Successfully refreshed OAuth2 token', {
        scopes: token.scope,
        expiresIn: token.expiresIn
      });
      
      return token;
    } catch (error) {
      this.logger.error('Failed to refresh OAuth2 token', { error });
      throw new Error(`OAuth2 token refresh failed: ${this.formatError(error)}`);
    }
  }

  /**
   * Formats error objects into consistent error messages
   * @param error Any error object to format
   * @returns Formatted error message string
   */
  private formatError(error: unknown): string {
    if (axios.isAxiosError(error)) {
      if (error.response) {
        const status = error.response.status;
        const message = error.response.data?.message || 'Unknown error';
        const details = error.response.data?.errors 
          ? ` (Details: ${JSON.stringify(error.response.data.errors)})` 
          : '';
        return `${status} - ${message}${details}`;
      } else if (error.request) {
        return 'No response received from GitHub API';
      } else {
        return `Request setup error: ${error.message}`;
      }
    } else if (error instanceof Error) {
      return error.message;
    } else {
      return String(error);
    }
  }

  /**
   * Validates if a token is still valid and returns its associated information
   * @param token GitHub token to validate
   * @returns Validation result with token information
   */
  public async validateToken(token: string): Promise<{
    valid: boolean;
    scopes: string[];
    username?: string;
    rateLimitInfo?: RateLimitInfo;
    error?: string;
  }> {
    try {
      const { username, tokenScopes } = await this.getUserInfo(token);
      
      const response = await this.makeRequestWithRetry({
        url: '/rate_limit',
        method: 'GET',
        headers: {
          Authorization: `token ${token}`
        }
      });
      
      const rateLimitInfo = this.parseRateLimitHeaders(response);
      
      this.logger.info('Token validation successful', {
        username,
        scopes: tokenScopes,
        valid: true
      });
      
      return {
        valid: true,
        scopes: tokenScopes,
        username,
        rateLimitInfo
      };
    } catch (error) {
      const formattedError = this.formatError(error);
      this.logger.warn('Token validation failed', { error: formattedError });
      
      return {
        valid: false,
        scopes: [],
        error: formattedError
      };
    }
  }

  /**
   * Checks if a token is expired based on its expiration date
   * @param token GitHub token to check
   * @returns True if token is expired or about to expire (within 5 minutes)
   */
  public isTokenExpired(token: GitHubToken): boolean {
    if (token.expiresAt) {
      return new Date() > token.expiresAt;
    }
    return false;
  }

  /**
   * Creates an authorization URL for OAuth2 flow
   * @param state Random state string for CSRF protection
   * @returns Complete authorization URL
   */
  public getAuthorizationUrl(state: string): string {
    if (!this.oauth2Config) {
      throw new Error('OAuth2 configuration is required for this operation');
    }
    
    const authEndpoint = this.oauth2Config.authorizationEndpoint || 
      `${this.authBaseUrl}/login/oauth/authorize`;
    
    const params = new URLSearchParams({
      client_id: this.oauth2Config.clientId,
      redirect_uri: this.oauth2Config.redirectUri,
      scope: this.oauth2Config.scope.join(' '),
      state,
      response_type: 'code'
    });
    
    return `${authEndpoint}?${params.toString()}`;
  }

  /**
   * Handles automatic token refresh if needed
   * @param token Current GitHub token information
   * @returns Refreshed token or original if refresh not needed/possible
   */
  public async ensureFreshToken(token: GitHubToken): Promise<GitHubToken> {
    // If token is not expired or doesn't have an expiry date, return as is
    if (!this.isTokenExpired(token)) {
      return token;
    }
    
    // If we don't have a refresh token, we can't refresh
    if (!token.refreshToken) {
      this.logger.warn('Token is expired but no refresh token is available');
      return token;
    }
    
    try {
      this.logger.info('Token is expired, attempting to refresh');
      return await this.refreshOAuth2Token(token.refreshToken);
    } catch (error) {
      this.logger.error('Failed to refresh token', { error: this.formatError(error) });
      // Return original token even though it's expired
      return token;
    }
  }

  /**
   * Creates a new personal access token with specified scopes
   * @param token Current GitHub token
   * @param note Description for the new token
   * @param scopes Required scopes for the new token
   * @returns New token information
   */
  public async createPersonalAccessToken(
    token: string,
    note: string,
    scopes: string[]
  ): Promise<{ tokenId: string; token: string }> {
    try {
      const response = await this.makeRequestWithRetry<{ id: string; token: string }>({
        url: '/authorizations',
        method: 'POST',
        headers: GitHubRotator.authHeader(token),
        data: {
          scopes,
          note,
          fingerprint: `token-guardian-${Date.now()}`
        }
      });
      
      this.logger.info('Successfully created new personal access token', {
        note,
        scopes
      });
      
      return {
        tokenId: response.data.id,
        token: response.data.token
      };
    } catch (error) {
      this.logger.error('Failed to create personal access token', { 
        error: this.formatError(error),
        note,
        scopes 
      });
      throw new Error(`Failed to create personal access token: ${this.formatError(error)}`);
    }
  }

  /**
   * Deletes a personal access token by its ID
   * @param token Current GitHub token
   * @param tokenId ID of the token to delete
   * @returns True if deletion was successful
   */
  public async deletePersonalAccessToken(token: string, tokenId: string): Promise<boolean> {
    try {
      // First validate that the token still exists
      try {
        await this.makeRequestWithRetry({
          url: `/authorizations/${tokenId}`,
          method: 'GET',
          headers: {
            Authorization: `token ${token}`
          }
        });
      } catch (checkError) {
        if (axios.isAxiosError(checkError) && checkError.response?.status === 404) {
          this.logger.info('Token already deleted or does not exist', { tokenId });
          return true; // Consider it a success if token is already gone
        }
        // For other errors during check, continue with deletion attempt
      }
      
      await this.makeRequestWithRetry({
        url: `/authorizations/${tokenId}`,
        method: 'DELETE',
        headers: {
          Authorization: `token ${token}`
        }
      });
      
      this.logger.info('Successfully deleted personal access token', { tokenId });
      return true;
    } catch (error) {
      this.logger.error('Failed to delete personal access token', { 
        error: this.formatError(error),
        tokenId 
      });
      return false;
    }
  }

  /**
   * Rotates a GitHub token by creating a new one and deleting the old one
   * @param tokenName The name/identifier of the token
   * @param currentToken The current token value
   * @returns Result of the rotation
   */
  public async rotateToken(tokenName: string, currentToken: string): Promise<RotationResult> {
    try {
      // Step 1: Validate the current token and gather its scope information
      let tokenScopes: string[] = [];
      let username: string = '';
      
      try {
        const userInfo = await this.getUserInfo(currentToken);
        tokenScopes = userInfo.tokenScopes;
        username = userInfo.username;
        
        this.logger.info('Validated existing token for rotation', {
          tokenName,
          username,
          scopes: tokenScopes
        });
      } catch (error) {
        const formattedError = this.formatError(error);
        this.logger.error('Failed to validate token for rotation', {
          tokenName,
          error: formattedError
        });
        
        if (axios.isAxiosError(error) && error.response?.status === 401) {
          return {
            success: false,
            message: 'Current GitHub token is invalid or expired',
            newExpiry: null
          };
        }
        throw error; // Re-throw for the outer catch block
      }
      
      if (!tokenScopes.length) {
        this.logger.warn('No scopes available for token rotation', { tokenName });
        return {
          success: false,
          message: 'Could not determine token scopes for rotation',
          newExpiry: null
        };
      }
      
      // Step 2: Create a new token with the same scopes via GitHub API
      const note = `TokenGuardian Rotated Token (${new Date().toISOString()})`;
      
      this.logger.info('Creating new token with matching scopes', {
        tokenName,
        scopes: tokenScopes,
        note
      });
      
      let newToken: string;
      let tokenId: string;
      
      try {
        // Use our optimized method for creating a token
        const tokenResult = await this.createPersonalAccessToken(
          currentToken,
          note,
          tokenScopes
        );
        
        newToken = tokenResult.token;
        tokenId = tokenResult.tokenId;
        
        this.logger.info('Successfully created new token', {
          tokenName,
          tokenId
        });
      } catch (error) {
        // This is a critical failure - we couldn't create a new token
        const formattedError = this.formatError(error);
        this.logger.error('Failed to create new token during rotation', {
          tokenName,
          error: formattedError
        });
        
        return {
          success: false,
          message: `Failed to create new GitHub token: ${formattedError}`,
          newExpiry: null
        };
      }
      
      // If we got this far, we have a new token
      // Step 3: Verify the new token works
      try {
        this.logger.info('Validating new token', { tokenName });
        const validationResult = await this.validateToken(newToken);
        
        if (!validationResult.valid) {
          this.logger.error('New token validation failed', { tokenName });
          return {
            success: false,
            message: 'Created new GitHub token, but validation failed',
            newExpiry: null
          };
        }
        
        this.logger.info('New token validated successfully', { 
          tokenName,
          scopes: validationResult.scopes 
        });
      } catch (error) {
        const formattedError = this.formatError(error);
        this.logger.error('Exception during new token validation', { 
          tokenName, 
          error: formattedError 
        });
        
        // We created a token but can't verify it - return it anyway but with a warning
        return {
          success: true,
          message: `GitHub token rotated, but validation failed: ${formattedError}`,
          newToken,
          newExpiry: null,
          warnings: [`Token validation failed: ${formattedError}`]
        };
      }
      
      // Step 4: Delete the old token for cleanup if possible
      let cleanupSuccess = false;
      try {
        this.logger.info('Attempting to delete old token for cleanup', { tokenName });
        
        // Check if we have enough permissions to delete tokens
        if (tokenScopes.includes('delete_repo') || tokenScopes.includes('admin:org')) {
          // We don't have the ID of the old token, so we need to list all tokens
          // and find the ones that aren't our new token
          const response = await this.makeRequestWithRetry<Array<{ note?: string; token_last_eight?: string; id: string }>>({
            url: '/authorizations',
            method: 'GET',
            headers: GitHubRotator.authHeader(currentToken)
          });
          
          // Find tokens that match our naming pattern but aren't the new one
          const oldTokens = response.data.filter(token => 
            token.note && token.note.includes('TokenGuardian') && token.token_last_eight !== newToken.slice(-8)
          );
          
          if (oldTokens.length > 0) {
            this.logger.info(`Found ${oldTokens.length} old tokens to clean up`, { tokenName });
            
            // Delete old tokens in parallel for efficiency
            const deletionResults = await Promise.all(
              oldTokens.map((t: { id: string }) => this.deletePersonalAccessToken(currentToken, t.id))
            );
            
            cleanupSuccess = deletionResults.some(result => result === true);
            this.logger.info(`Deleted ${deletionResults.filter(Boolean).length}/${oldTokens.length} old tokens`, {
              tokenName,
              success: cleanupSuccess
            });
          } else {
            this.logger.info('No old tokens found for cleanup', { tokenName });
          }
        } else {
          this.logger.warn('Insufficient permissions to delete old tokens', { 
            tokenName,
            scopes: tokenScopes
          });
        }
      } catch (error) {
        const formattedError = this.formatError(error);
        this.logger.warn('Failed to clean up old tokens', { 
          tokenName, 
          error: formattedError 
        });
        // We don't fail the rotation if cleanup fails
      }
      
      // Step 5: Return successful rotation result
      // GitHub tokens don't have an expiry by default
      return {
        success: true,
        message: cleanupSuccess 
          ? 'GitHub token rotated successfully with cleanup' 
          : 'GitHub token rotated successfully',
        newToken,
        newExpiry: null,
        warnings: cleanupSuccess ? undefined : ['Old token could not be deleted']
      };
    } catch (error) {
      // Catch-all error handler for unexpected issues
      let errorMessage = 'Unknown error during GitHub token rotation';
      
      if (axios.isAxiosError(error)) {
        if (error.response) {
          errorMessage = `GitHub API error: ${error.response.status} - ${error.response.data?.message || 'Unknown error'}`;
          
          // Add detailed errors if available
          if (error.response.data?.errors) {
            errorMessage += ` (Details: ${JSON.stringify(error.response.data.errors)})`;
          }
          
          // Special handling for specific error codes
          if (error.response.status === 403 && error.response.data?.message?.includes('rate limit')) {
            errorMessage = `GitHub API rate limit exceeded. Try again after ${new Date(
              parseInt(error.response.headers['x-ratelimit-reset'] as string, 10) * 1000
            ).toLocaleString()}`;
          } else if (error.response.status === 422) {
            errorMessage = `GitHub API validation error: ${error.response.data?.message}`;
          }
        } else if (error.request) {
          errorMessage = 'No response received from GitHub API';
        } else {
          errorMessage = `Error setting up request: ${error.message}`;
        }
      } else if (error instanceof Error) {
        errorMessage = `Error rotating GitHub token: ${error.message}`;
      }
      
      this.logger.error('GitHub token rotation failed', {
        error: errorMessage,
        stack: error instanceof Error ? error.stack : undefined
      });
      
      return {
        success: false,
        message: errorMessage,
        newExpiry: null
      };
    }
  }
}
