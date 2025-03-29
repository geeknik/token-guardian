# TokenGuardian

🔒 Zero-trust token security, leak prevention and rotation automation for Node.js applications

![npm version](https://img.shields.io/npm/v/token-guardian)
![build status](https://img.shields.io/github/workflow/status/geeknik/token-guardian/CI)
![license](https://img.shields.io/npm/l/token-guardian)

## The Problem

API tokens, JWT tokens, and secrets are constantly leaked through accidental commits, environment misconfigurations, and poor rotation practices. Once exposed, these tokens create significant security vulnerabilities that often go undetected until it's too late.

## The Solution

TokenGuardian provides multi-layered protection for your tokens and secrets:

1. **Leak Prevention** - Git pre-commit hooks that scan for potential token patterns across multiple formats
2. **Validation** - Runtime token validation that verifies entropy and format compliance
3. **Rotation** - Fully automated token rotation capabilities with common services (AWS, GitHub, etc.)
4. **Monitoring** - Token canary system that alerts when exposed credentials are used
5. **Tracking** - Fingerprinting to track token usage across systems

## Installation

```bash
npm install token-guardian
```

## Usage

```typescript
import { TokenGuardian } from 'token-guardian';

// Initialize TokenGuardian with your configuration
const guardian = new TokenGuardian({
  services: ['github', 'aws'],
  rotationInterval: '7d',
  canaryEnabled: true
});

// Check if a string contains potential tokens or secrets
const hasSensitiveData = guardian.scanString('My API key is sk_test_1234567890abcdef');

// Protect your GitHub token and enable rotation
guardian.protect('GITHUB_TOKEN', process.env.GITHUB_TOKEN, {
  rotationEnabled: true,
  canaryEnabled: true,
  serviceType: 'github'
});

// Protect your AWS credentials and enable rotation
// AWS credentials must be in format "ACCESS_KEY_ID:SECRET_ACCESS_KEY"
guardian.protect('AWS_CREDENTIALS', `${process.env.AWS_ACCESS_KEY_ID}:${process.env.AWS_SECRET_ACCESS_KEY}`, {
  rotationEnabled: true,
  canaryEnabled: true,
  serviceType: 'aws'
});

// Get a protected token
const token = guardian.getToken('GITHUB_TOKEN');

// Manually rotate a token
await guardian.rotateToken('AWS_CREDENTIALS');
```

## Features

### 🔍 Token Detection

TokenGuardian can detect over 150 different token formats, including:

- API Keys (AWS, GitHub, Stripe, etc.)
- JWT Tokens
- OAuth Tokens
- Private Keys (SSH, RSA, etc.)
- Cryptocurrency Private Keys
- Database Connection Strings

### 🔄 Automated Rotation

TokenGuardian provides actual working rotation for supported services:

- **AWS IAM Keys**: Securely rotates IAM access keys with proper verification
- **GitHub Tokens**: Full API-based rotation with scope preservation
- **Custom Services**: Extensible framework for adding more services

### 🕵️ Canary Tokens

Embed undetectable canary markers in your tokens to be alerted when they're used outside your authorized systems. Supports clever embedding in:

- JWT tokens (preserves functionality while adding tracking)
- Long string tokens (minimal modifications that maintain functionality)
- Multiple format-specific strategies for optimal tracking

### 🔐 Token Storage

All sensitive data is encrypted at rest using AES-256-CBC with:
- Per-token encryption to minimize exposure
- Secure key derivation
- Comprehensive audit logging

### 🌐 Token Fingerprinting

Track where and how your tokens are being used across your infrastructure:
- Usage patterns
- Access timestamps
- Anomaly detection

## Security

TokenGuardian takes a zero-trust approach to token security. All sensitive data is encrypted at rest and in transit, and we implement defense-in-depth with multiple layers of protection.

## License

MIT
