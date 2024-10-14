package com.awsassociatetraining.iam;

import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;

import static com.awsassociatetraining.utils.IAMUtility.isUserInGroup;

public class IAMUsersTest {
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
    public void validateFullAccessUserEC2() {
        String expectedUserName = "FullAccessUserEC2";
        String expectedGroupName = "FullAccessGroupEC2";
        Assert.assertTrue(isUserInGroup(iamClient, expectedUserName, expectedGroupName));
    }

    @Test
    public void validateFullAccessUserS3() {
        String expectedUserName = "FullAccessUserS3";
        String expectedGroupName = "FullAccessGroupS3";
        Assert.assertTrue(isUserInGroup(iamClient, expectedUserName, expectedGroupName));
    }

    @Test
    public void validateReadAccessUserS3() {
        String expectedUserName = "ReadAccessUserS3";
        String expectedGroupName = "ReadAccessGroupS3";
        Assert.assertTrue(isUserInGroup(iamClient, expectedUserName, expectedGroupName));
    }

    @AfterTest
    public void tearDown() {
        iamClient.close();
    }
}
