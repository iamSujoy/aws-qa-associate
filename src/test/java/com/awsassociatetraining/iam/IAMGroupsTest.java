package com.awsassociatetraining.iam;

import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;

import static com.awsassociatetraining.utils.IAMUtility.groupHasAttachedPolicy;

public class IAMGroupsTest {
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
    public void validateFullAccessGroupEC2() {
        String expectedGroupName = "FullAccessGroupEC2";
        String expectedPolicyName = "FullAccessPolicyEC2";
        Assert.assertTrue(groupHasAttachedPolicy(iamClient, expectedGroupName, expectedPolicyName));
    }

    @Test
    public void validateFullAccessGroupS3() {
        String expectedGroupName = "FullAccessGroupS3";
        String expectedPolicyName = "FullAccessPolicyS3";
        Assert.assertTrue(groupHasAttachedPolicy(iamClient, expectedGroupName, expectedPolicyName));
    }

    @Test
    public void validateReadAccessGroupS3() {
        String expectedGroupName = "ReadAccessGroupS3";
        String expectedPolicyName = "ReadAccessPolicyS3";
        Assert.assertTrue(groupHasAttachedPolicy(iamClient, expectedGroupName, expectedPolicyName));
    }

    @AfterTest
    public void tearDown() {
        iamClient.close();
    }
}
