# TokenGuardian

🔒 Zero-trust token security, leak prevention and rotation automation for Node.js applications

[![npm version](https://img.shields.io/npm/v/token-guardian)](https://www.npmjs.com/package/token-guardian)
[![CI](https://img.shields.io/github/actions/workflow/status/geeknik/token-guardian/ci.yml?branch=main&label=tests)](https://github.com/geeknik/token-guardian/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/geeknik/token-guardian/ci.yml?branch=main&label=codeql&logo=github)](https://github.com/geeknik/token-guardian/security/code-scanning)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

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

// Pause scheduled rotation if you need to take a token out of circulation temporarily
guardian.stopRotation('GITHUB_TOKEN');

// Stop all scheduled rotations (useful during shutdown or maintenance)
guardian.stopAllRotations();
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
- **Rotation Controls**: Explicitly pause rotation per token or stop all schedules during shutdown

Rotation intervals are validated (positive integers followed by `d`, `h`, `m`, or `s`). Invalid inputs automatically fall back to the configured default (30d by default).

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

## CI/CD and GitHub Workflows

To use the included CI/CD workflows, copy the workflow files into your GitHub repository:

1. Create the `.github/workflows` directory
2. Copy `ci-workflow.yml` to `.github/workflows/ci.yml`
3. Copy `release-workflow.yml` to `.github/workflows/release.yml`

These workflows will:
- Run tests on multiple Node.js versions
- Perform security scanning with CodeQL
- Publish releases to npm

## Security

TokenGuardian takes a zero-trust approach to token security. All sensitive data is encrypted at rest and in transit, and we implement defense-in-depth with multiple layers of protection.

## License

MIT
