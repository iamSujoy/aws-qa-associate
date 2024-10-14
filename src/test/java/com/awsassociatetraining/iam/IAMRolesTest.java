package com.awsassociatetraining.iam;

import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;

import static com.awsassociatetraining.utils.IAMUtility.roleHasAttachedPolicy;

public class IAMRolesTest {
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
    public void validateFullAccessRoleEC2() {
        String expectedRoleName = "FullAccessRoleEC2";
        String expectedPolicyName = "FullAccessPolicyEC2";
        Assert.assertTrue(roleHasAttachedPolicy(iamClient, expectedRoleName, expectedPolicyName));
    }

    @Test
    public void validateFullAccessRoleS3() {
        String expectedRoleName = "FullAccessRoleS3";
        String expectedPolicyName = "FullAccessPolicyS3";
        Assert.assertTrue(roleHasAttachedPolicy(iamClient, expectedRoleName, expectedPolicyName));
    }

    @Test
    public void validateReadAccessRoleS3() {
        String expectedRoleName = "ReadAccessRoleS3";
        String expectedPolicyName = "ReadAccessPolicyS3";
        Assert.assertTrue(roleHasAttachedPolicy(iamClient, expectedRoleName, expectedPolicyName));
    }

    @AfterTest
    public void tearDown() {
        iamClient.close();
    }
}
