import { ServiceRotator } from '../ServiceRotator';
import { RotationResult } from '../../interfaces/RotationResult';
import crypto from 'crypto';
import axios from 'axios';

/**
 * Interface representing an AWS API request
 */
interface AWSRequest {
  host: string;
  method: string;
  path: string;
  region: string;
  service: string;
  headers: Record<string, string>;
  params?: Record<string, string>;
}

/**
 * Rotator for AWS access keys
 */
export class AWSRotator implements ServiceRotator {
  // AWS region to use for API calls
  private region: string = 'us-east-1';
  // Endpoint for AWS STS service
  private stsEndpoint: string = 'https://sts.amazonaws.com';
  // Endpoint for AWS IAM service
  private iamEndpoint: string = 'https://iam.amazonaws.com';
  
  /**
   * Rotates an AWS access key using the AWS API
   * @param tokenName The name/identifier of the token
   * @param currentToken The current token value in format "ACCESS_KEY_ID:SECRET_ACCESS_KEY"
   * @returns Result of the rotation
   */
  public async rotateToken(tokenName: string, currentToken: string): Promise<RotationResult> {
    try {
      // Parse the current token into access key ID and secret
      const [accessKeyId, secretAccessKey] = currentToken.split(':');
      
      if (!accessKeyId || !secretAccessKey) {
        return {
          success: false,
          message: 'Invalid AWS credentials format. Expected "ACCESS_KEY_ID:SECRET_ACCESS_KEY"',
          newExpiry: null
        };
      }
      
      // Step 1: Validate the current credentials by calling STS GetCallerIdentity
      let username: string;
      try {
        username = await this.getCurrentUser(accessKeyId, secretAccessKey);
      } catch (error) {
        return {
          success: false,
          message: `Current AWS credentials are invalid: ${error instanceof Error ? error.message : 'Unknown error'}`,
          newExpiry: null
        };
      }
      
      // Step 2: Check how many access keys the user already has
      // AWS limits users to 2 access keys per user
      const userKeys = await this.listAccessKeys(accessKeyId, secretAccessKey, username);
      
      if (userKeys.length >= 2) {
        // If we already have 2 keys (including the current one), we need to delete the other non-current key
        const otherKey = userKeys.find(key => key !== accessKeyId);
        if (otherKey) {
          await this.deleteAccessKey(accessKeyId, secretAccessKey, username, otherKey);
        }
      }
      
      // Step 3: Create a new access key
      const newKey = await this.createAccessKey(accessKeyId, secretAccessKey, username);
      const newKeyPair = `${newKey.accessKeyId}:${newKey.secretAccessKey}`;
      
      // Step 4: Verify the new key works
      try {
        await this.getCurrentUser(newKey.accessKeyId, newKey.secretAccessKey);
      } catch (error) {
        // If verification fails, attempt to delete the new key and fail
        try {
          await this.deleteAccessKey(accessKeyId, secretAccessKey, username, newKey.accessKeyId);
        } catch {
          // Ignore cleanup errors, focus on the primary issue
        }
        
        return {
          success: false,
          message: `New AWS credentials verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          newExpiry: null
        };
      }
      
      // Step 5: Schedule deletion of the old key (with a safety delay)
      // In a real system, we would wait to ensure the new key is distributed to all services
      // For now, we'll proceed with immediate deletion for demonstration purposes
      try {
        await this.deleteAccessKey(newKey.accessKeyId, newKey.secretAccessKey, username, accessKeyId);
      } catch (error) {
        // Log but continue - we have new working credentials
        console.error('Failed to delete old AWS access key:', error);
      }
      
      // Return the new credentials
      // AWS access keys don't have an expiry by default
      return {
        success: true,
        message: 'AWS access key rotated successfully',
        newToken: newKeyPair,
        newExpiry: null
      };
    } catch (error) {
      return {
        success: false,
        message: `Error rotating AWS key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        newExpiry: null
      };
    }
  }
  
  /**
   * Gets the current IAM user associated with the credentials
   * @param accessKeyId AWS access key ID
   * @param secretAccessKey AWS secret access key
   * @returns IAM username
   */
  private async getCurrentUser(accessKeyId: string, secretAccessKey: string): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
    const _date = timestamp.slice(0, 8);
    
    const request = {
      host: new URL(this.stsEndpoint).host,
      method: 'GET',
      path: '/',
      region: this.region,
      service: 'sts',
      headers: {
        'Host': new URL(this.stsEndpoint).host,
        'X-Amz-Date': timestamp
      },
      params: {
        'Action': 'GetCallerIdentity',
        'Version': '2011-06-15'
      }
    };
    
    const signedRequest = this.signAwsRequest(request, accessKeyId, secretAccessKey);
    
    const response = await axios.get(this.stsEndpoint, {
      params: request.params,
      headers: signedRequest.headers
    });
    
    // Parse XML response to extract username
    const xml = response.data;
    const match = /<Arn>arn:aws:iam::\d+:user\/([^<]+)<\/Arn>/.exec(xml);
    
    if (!match || !match[1]) {
      throw new Error('Could not extract IAM username from response');
    }
    
    return match[1];
  }
  
  /**
   * Lists access keys for the specified IAM user
   * @param accessKeyId AWS access key ID
   * @param secretAccessKey AWS secret access key
   * @param username IAM username
   * @returns Array of access key IDs
   */
  private async listAccessKeys(accessKeyId: string, secretAccessKey: string, username: string): Promise<string[]> {
    const timestamp = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
    const _date = timestamp.slice(0, 8);
    
    const request = {
      host: new URL(this.iamEndpoint).host,
      method: 'GET',
      path: '/',
      region: this.region,
      service: 'iam',
      headers: {
        'Host': new URL(this.iamEndpoint).host,
        'X-Amz-Date': timestamp
      },
      params: {
        'Action': 'ListAccessKeys',
        'UserName': username,
        'Version': '2010-05-08'
      }
    };
    
    const signedRequest = this.signAwsRequest(request, accessKeyId, secretAccessKey);
    
    const response = await axios.get(this.iamEndpoint, {
      params: request.params,
      headers: signedRequest.headers
    });
    
    // Parse XML response to extract key IDs
    const xml = response.data;
    const keys: string[] = [];
    
    // Use regex to extract access key IDs from XML
    const regex = /<AccessKeyId>([^<]+)<\/AccessKeyId>/g;
    let match;
    while ((match = regex.exec(xml)) !== null) {
      keys.push(match[1]);
    }
    
    return keys;
  }
  
  /**
   * Creates a new access key for the specified IAM user
   * @param accessKeyId AWS access key ID
   * @param secretAccessKey AWS secret access key
   * @param username IAM username
   * @returns Object containing the new access key ID and secret
   */
  private async createAccessKey(accessKeyId: string, secretAccessKey: string, username: string): Promise<{accessKeyId: string, secretAccessKey: string}> {
    const timestamp = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
    const _date = timestamp.slice(0, 8);
    
    const request = {
      host: new URL(this.iamEndpoint).host,
      method: 'GET',
      path: '/',
      region: this.region,
      service: 'iam',
      headers: {
        'Host': new URL(this.iamEndpoint).host,
        'X-Amz-Date': timestamp
      },
      params: {
        'Action': 'CreateAccessKey',
        'UserName': username,
        'Version': '2010-05-08'
      }
    };
    
    const signedRequest = this.signAwsRequest(request, accessKeyId, secretAccessKey);
    
    const response = await axios.get(this.iamEndpoint, {
      params: request.params,
      headers: signedRequest.headers
    });
    
    // Parse XML response to extract new key details
    const xml = response.data;
    
    const accessKeyIdMatch = /<AccessKeyId>([^<]+)<\/AccessKeyId>/.exec(xml);
    const secretAccessKeyMatch = /<SecretAccessKey>([^<]+)<\/SecretAccessKey>/.exec(xml);
    
    if (!accessKeyIdMatch || !accessKeyIdMatch[1] || !secretAccessKeyMatch || !secretAccessKeyMatch[1]) {
      throw new Error('Could not extract new access key from response');
    }
    
    return {
      accessKeyId: accessKeyIdMatch[1],
      secretAccessKey: secretAccessKeyMatch[1]
    };
  }
  
  /**
   * Deletes an access key for the specified IAM user
   * @param accessKeyId AWS access key ID (for auth)
   * @param secretAccessKey AWS secret access key (for auth)
   * @param username IAM username
   * @param keyToDelete Access key ID to delete
   */
  private async deleteAccessKey(accessKeyId: string, secretAccessKey: string, username: string, keyToDelete: string): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
    const _date = timestamp.slice(0, 8);
    
    const request = {
      host: new URL(this.iamEndpoint).host,
      method: 'GET',
      path: '/',
      region: this.region,
      service: 'iam',
      headers: {
        'Host': new URL(this.iamEndpoint).host,
        'X-Amz-Date': timestamp
      },
      params: {
        'Action': 'DeleteAccessKey',
        'UserName': username,
        'AccessKeyId': keyToDelete,
        'Version': '2010-05-08'
      }
    };
    
    const signedRequest = this.signAwsRequest(request, accessKeyId, secretAccessKey);
    
    await axios.get(this.iamEndpoint, {
      params: request.params,
      headers: signedRequest.headers
    });
  }
  
  /**
   * Signs an AWS request using Signature Version 4
   * @param request Request object to sign
   * @param accessKey AWS access key ID
   * @param secretKey AWS secret access key
   * @returns Signed request with authorization headers
   */
  private signAwsRequest(request: AWSRequest, accessKey: string, secretKey: string): AWSRequest {
    const timestamp = request.headers['X-Amz-Date'];
    const _date = timestamp.slice(0, 8);
    
    // Create canonical request
    const canonical = this.createCanonicalRequest(request);
    
    // Create string to sign
    const credentialScope = `${_date}/${request.region}/${request.service}/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      timestamp,
      credentialScope,
      this.hash(canonical)
    ].join('\n');
    
    // Calculate signature
    const kDate = this.hmac('AWS4' + secretKey, _date);
    const kRegion = this.hmac(kDate, request.region);
    const kService = this.hmac(kRegion, request.service);
    const kSigning = this.hmac(kService, 'aws4_request');
    const signature = this.hmacHex(kSigning, stringToSign);
    
    // Add authorization header
    request.headers['Authorization'] = [
      `AWS4-HMAC-SHA256 Credential=${accessKey}/${credentialScope}`,
      `SignedHeaders=${Object.keys(request.headers).map(h => h.toLowerCase()).sort().join(';')}`,
      `Signature=${signature}`
    ].join(', ');
    
    return request;
  }
  
  /**
   * Creates a canonical request for AWS Signature Version 4
   * @param request Request object
   * @returns Canonical request string
   */
  private createCanonicalRequest(request: AWSRequest): string {
    // Create canonical query string
    const params = request.params || {};
    const canonicalQueryString = Object.keys(params)
      .sort()
      .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(params[key])}`)
      .join('&');
    
    // Create canonical headers
    const canonicalHeaders = Object.keys(request.headers)
      .map(key => key.toLowerCase())
      .sort()
      .map(key => `${key}:${request.headers[key].trim()}`)
      .join('\n') + '\n';
    
    // Create signed headers list
    const signedHeaders = Object.keys(request.headers)
      .map(key => key.toLowerCase())
      .sort()
      .join(';');
    
    // Combine canonical components
    return [
      request.method,
      request.path,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      'UNSIGNED-PAYLOAD'
    ].join('\n');
  }
  
  /**
   * Calculates SHA-256 hash of a string
   * @param data Data to hash
   * @returns Hex-encoded hash
   */
  private hash(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }
  
  /**
   * Calculates HMAC using SHA-256
   * @param key Key for HMAC
   * @param data Data to sign
   * @returns Buffer containing HMAC
   */
  private hmac(key: string | Buffer, data: string): Buffer {
    const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, 'utf8');
    return crypto.createHmac('sha256', keyBuffer).update(data).digest();
  }
  
  /**
   * Calculates HMAC using SHA-256 and converts to hex
   * @param key Key for HMAC
   * @param data Data to sign
   * @returns Hex-encoded HMAC
   */
  private hmacHex(key: string | Buffer, data: string): string {
    const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, 'utf8');
    return crypto.createHmac('sha256', keyBuffer).update(data).digest('hex');
  }
}
