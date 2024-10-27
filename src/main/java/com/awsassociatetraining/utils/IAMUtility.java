package com.awsassociatetraining.utils;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class IAMUtility {

    public static boolean isUserInGroup(IamClient iamClient, String userName, String expectedGroupName) {
        try {
            ListUsersResponse listUsersResponse = iamClient.listUsers();
            List<User> users = listUsersResponse.users();

            User user = users.stream()
                    .filter(u -> u.userName().equals(userName))
                    .findFirst()
                    .orElse(null);

            if (user == null) return false;

            ListGroupsForUserResponse groupsForUserResponse = iamClient.listGroupsForUser(builder ->
                    builder.userName(userName));
            List<Group> userGroups = groupsForUserResponse.groups();

            return userGroups.stream()
                    .anyMatch(group -> group.groupName().equals(expectedGroupName));

        } catch (IamException e) {
            System.err.println("IAM error occurred: " + e);
        }
        return false;
    }

    public static boolean groupHasAttachedPolicy(IamClient iamClient, String groupName, String expectedPolicyName) {
        try {
            ListGroupsResponse listGroupsResponse = iamClient.listGroups();
            List<Group> groups = listGroupsResponse.groups();

            Group group = groups.stream()
                    .filter(g -> g.groupName().equals(groupName))
                    .findFirst()
                    .orElse(null);

            if (group == null) return false;

            ListAttachedGroupPoliciesResponse listPoliciesResponse = iamClient.listAttachedGroupPolicies(builder ->
                    builder.groupName(groupName));
            List<AttachedPolicy> attachedPolicies = listPoliciesResponse.attachedPolicies();

            return attachedPolicies.stream()
                    .anyMatch(p -> p.policyName().equals(expectedPolicyName));

        } catch (IamException e) {
            System.err.println("IAM error occurred: " + e);
        }
        return false;
    }

    public static boolean roleHasAttachedPolicy(IamClient iamClient, String expectedRoleName, String expectedPolicyName) {
        try {
            ListRolesResponse listRolesResponse = iamClient.listRoles();
            List<Role> roles = listRolesResponse.roles();

            Role role = roles.stream()
                    .filter(r -> r.roleName().equals(expectedRoleName))
                    .findFirst()
                    .orElse(null);

            if (role == null) return false;

            ListAttachedRolePoliciesResponse listPoliciesResponse = iamClient.listAttachedRolePolicies(builder ->
                    builder.roleName(expectedRoleName));
            List<AttachedPolicy> attachedPolicies = listPoliciesResponse.attachedPolicies();

            return attachedPolicies.stream()
                    .anyMatch(p -> p.policyName().equals(expectedPolicyName));

        } catch (IamException e) {
            System.err.println("IAM error occurred: " + e);
        }
        return false;
    }

    public static String getPolicyStatement(IamClient iamClient, String policyName) {
        try {
            ListPoliciesResponse listPoliciesResponse = iamClient.listPolicies();
            List<Policy> policies = listPoliciesResponse.policies();

            Policy policy = policies.stream()
                    .filter(p -> p.policyName().equals(policyName))
                    .findFirst()
                    .orElse(null);

            if (policy == null) return null;

            GetPolicyResponse getPolicyResponse = iamClient.getPolicy(builder -> builder.policyArn(policy.arn()));
            String defaultVersionId = getPolicyResponse.policy().defaultVersionId();

            GetPolicyVersionResponse versionResponse = iamClient.getPolicyVersion(builder ->
                    builder.policyArn(policy.arn()).versionId(defaultVersionId));

            String policyDocument = versionResponse.policyVersion().document();
            String decodedPolicyDocument = URLDecoder.decode(policyDocument, StandardCharsets.UTF_8.name());
            JsonElement jsonElement = JsonParser.parseString(decodedPolicyDocument);
            JsonObject jsonObject = jsonElement.getAsJsonObject();

            JsonElement statementElement = jsonObject.get("Statement");
            return statementElement.toString();

        } catch (IamException e) {
            System.err.println("IAM error occurred: " + e);
        } catch (UnsupportedEncodingException e) {
            System.err.println("IAM error occurred: " + e);
        }
        return null;
    }
}
