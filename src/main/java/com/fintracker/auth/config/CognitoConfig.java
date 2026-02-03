package com.fintracker.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;

/**
 * Configuration class for AWS Cognito integration.
 * Sets up the CognitoIdentityProviderClient bean with proper AWS credentials and region.
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Configuration
public class CognitoConfig {

    @Value("${aws.cognito.region}")
    private String region;

    /**
     * Creates and configures a CognitoIdentityProviderClient bean.
     * This client is used to interact with AWS Cognito User Pools for authentication operations.
     * 
     * The client uses the default AWS credentials provider chain, which looks for credentials in:
     * 1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
     * 2. System properties
     * 3. Credentials file (~/.aws/credentials)
     * 4. IAM instance profile
     * 
     * @return CognitoIdentityProviderClient configured with the specified region
     */
    @Bean
    public CognitoIdentityProviderClient cognitoClient() {
        return CognitoIdentityProviderClient.builder()
                .region(Region.of(region))
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }
}
