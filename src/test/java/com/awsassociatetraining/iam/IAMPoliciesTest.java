package com.awsassociatetraining.iam;

import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;

import static com.awsassociatetraining.utils.IAMUtility.getPolicyStatement;

public class IAMPoliciesTest {
    private Region region = Region.AWS_GLOBAL;
    private IamClient iamClient;

    @BeforeTest
    public void setup() {
        iamClient = IamClient.builder()
                .region(region)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }

    @Test
    public void validateFullAccessPolicyEC2() {
        String expectedPolicyName = "FullAccessPolicyEC2";
        String expectedPolicyStatement = "[{\"Action\":\"ec2:*\",\"Resource\":\"*\",\"Effect\":\"Allow\"}]";
        Assert.assertEquals(getPolicyStatement(iamClient, expectedPolicyName), expectedPolicyStatement);
    }

    @Test
    public void validateFullAccessPolicyS3() {
        String expectedPolicyName = "FullAccessPolicyS3";
        String expectedPolicyStatement = "[{\"Action\":\"s3:*\",\"Resource\":\"*\",\"Effect\":\"Allow\"}]";
        Assert.assertEquals(getPolicyStatement(iamClient, expectedPolicyName), expectedPolicyStatement);
    }

    @Test
    public void validateReadAccessPolicyS3() {
        String expectedPolicyName = "ReadAccessPolicyS3";
        String expectedPolicyStatement = "[{\"Action\":[\"s3:Describe*\",\"s3:Get*\",\"s3:List*\"],\"Resource\":\"*\",\"Effect\":\"Allow\"}]";
        Assert.assertEquals(getPolicyStatement(iamClient, expectedPolicyName), expectedPolicyStatement);
    }

    @AfterTest
    public void tearDown() {
        iamClient.close();
    }
}
