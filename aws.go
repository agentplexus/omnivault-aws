// Package aws provides OmniVault providers for AWS secret storage services.
//
// This package supports two AWS services:
//   - AWS Secrets Manager: For storing and rotating secrets (API keys, credentials, etc.)
//   - AWS Systems Manager Parameter Store: For configuration and secrets (often used for app config)
//
// Basic usage with Secrets Manager:
//
//	provider, err := aws.NewSecretsManager(aws.Config{
//	    Region: "us-east-1",
//	})
//	secret, err := provider.Get(ctx, "my-secret")
//
// Basic usage with Parameter Store:
//
//	provider, err := aws.NewParameterStore(aws.Config{
//	    Region: "us-east-1",
//	})
//	secret, err := provider.Get(ctx, "/myapp/database/password")
//
// With OmniVault client:
//
//	client, _ := omnivault.NewClient(omnivault.Config{
//	    CustomVault: aws.NewSecretsManager(aws.Config{}),
//	})
//
// On EKS with IRSA (IAM Roles for Service Accounts), authentication is automatic.
// Locally, use AWS credentials file, environment variables, or AWS SSO.
package aws

import (
	"github.com/aws/aws-sdk-go-v2/aws"
)

// Config holds configuration for AWS providers.
type Config struct {
	// Region is the AWS region (e.g., "us-east-1").
	// If empty, uses AWS_REGION env var or default region from AWS config.
	Region string

	// Profile is the AWS credentials profile name.
	// If empty, uses default profile or IAM role (IRSA on EKS).
	Profile string

	// EndpointURL is a custom endpoint URL (for LocalStack, testing, etc.).
	EndpointURL string

	// AWSConfig is an optional pre-configured AWS SDK config.
	// If provided, Region and Profile are ignored.
	AWSConfig *aws.Config
}
