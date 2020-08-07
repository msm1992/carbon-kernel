/*
 * Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 * 
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.user.core.ldap;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.user.api.NotImplementedException;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.RoleContext;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.util.JNDIUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.Secret;
import org.wso2.carbon.utils.UnsupportedSecretTypeException;

import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.TimeZone;
import javax.naming.Name;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InvalidAttributeIdentifierException;
import javax.naming.directory.InvalidAttributeValueException;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.NoSuchAttributeException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

/**
 * This class is responsible for manipulating Microsoft Active Directory(AD)and Active Directory
 * Light Directory Service (AD LDS)data. This class provides facility to add/delete/modify/view user
 * info in a directory server.
 */
public class ActiveDirectoryUserStoreManager extends ReadWriteLDAPUserStoreManager {

    private static Log logger = LogFactory.getLog(ActiveDirectoryUserStoreManager.class);
    private boolean isADLDSRole = false;
    private boolean isSSLConnection = false;
    private String userAccountControl = "512";
    private String userAttributeSeparator = ",";
    private static final String MULTI_ATTRIBUTE_SEPARATOR = "MultiAttributeSeparator";
    private static final String MULTI_ATTRIBUTE_SEPARATOR_DESCRIPTION = "This is the separator for multiple claim values";
    private static final ArrayList<Property> ACTIVE_DIRECTORY_UM_ADVANCED_PROPERTIES = new ArrayList<Property>();
    private static final String LDAPConnectionTimeout = "LDAPConnectionTimeout";
    private static final String LDAPConnectionTimeoutDescription = "LDAP Connection Timeout";
    private static final String BULK_IMPORT_SUPPORT = "BulkImportSupported";
    private static final String readTimeout = "ReadTimeout";
    private static final String readTimeoutDescription = "Configure this to define the read timeout for LDAP operations";
    private static final String RETRY_ATTEMPTS = "RetryAttempts";
    private static final String LDAPBinaryAttributesDescription = "Configure this to define the LDAP binary attributes " +
            "seperated by a space. Ex:mpegVideo mySpecialKey";
    private static final String WSO2_CLAIM_DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";
    private SimpleDateFormat scimDateFormat;
    private Calendar calendarForTimestampConversion;


    // For AD's this value is 1500 by default, hence overriding the default value.
    protected static final int MEMBERSHIP_ATTRIBUTE_RANGE_VALUE = 1500;

    static {
        setAdvancedProperties();
    }

    public ActiveDirectoryUserStoreManager() {

    }

    /**
     * @param realmConfig
     * @param properties
     * @param claimManager
     * @param profileManager
     * @param realm
     * @param tenantId
     * @throws UserStoreException
     */
    public ActiveDirectoryUserStoreManager(RealmConfiguration realmConfig,
                                           Map<String, Object> properties, ClaimManager claimManager,
                                           ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {

        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
        checkRequiredUserStoreConfigurations();
    }

    /**
     * @param realmConfig
     * @param claimManager
     * @param profileManager
     * @throws UserStoreException
     */
    public ActiveDirectoryUserStoreManager(RealmConfiguration realmConfig,
                                           ClaimManager claimManager, ProfileConfigurationManager profileManager)
            throws UserStoreException {
        super(realmConfig, claimManager, profileManager);
        checkRequiredUserStoreConfigurations();
    }

    /**
     *
     */
    public void doAddUser(String userName, Object credential, String[] roleList,
                          Map<String, String> claims, String profileName) throws UserStoreException {
        this.addUser(userName, credential, roleList, claims, profileName, false);
    }

    /**
     *
     */
    public void doAddUser(String userName, Object credential, String[] roleList,
                          Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException {

        boolean isUserBinded = false;

		/* getting search base directory context */
        DirContext dirContext = getSearchBaseDirectoryContext();

		/* getting add user basic attributes */
        BasicAttributes basicAttributes = getAddUserBasicAttributes(userName);

        if (!isADLDSRole) {
            // creating a disabled user account in AD DS
            BasicAttribute userAccountControl = new BasicAttribute(
                    LDAPConstants.ACTIVE_DIRECTORY_USER_ACCOUNT_CONTROL);
            userAccountControl.add(LDAPConstants.ACTIVE_DIRECTORY_DISABLED_NORMAL_ACCOUNT);
            basicAttributes.put(userAccountControl);
        }

		/* setting claims */
        setUserClaims(claims, basicAttributes, userName);

        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(credential);
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException("Unsupported credential type", e);
        }

        Name compoundName = null;
        try {
            NameParser ldapParser = dirContext.getNameParser("");
            compoundName = ldapParser.parse("cn=" + escapeSpecialCharactersForDN(userName));

            if (logger.isDebugEnabled()) {
                logger.debug("Binding user: " + compoundName);
            }

			/* bind the user. A disabled user account with no password */
            dirContext.bind(compoundName, null, basicAttributes);
            isUserBinded = true;

			/* update the user roles */
            doUpdateRoleListOfUser(userName, null, roleList);

			/* reset the password and enable the account */
            if (!isSSLConnection) {
                logger.warn("Unsecured connection is being used. Enabling user account operation will fail");
            }

            ModificationItem[] mods = new ModificationItem[2];
            mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(
                    LDAPConstants.ACTIVE_DIRECTORY_UNICODE_PASSWORD_ATTRIBUTE,
                    createUnicodePassword(credentialObj)));

            if (isADLDSRole) {
                mods[1] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(
                        LDAPConstants.ACTIVE_DIRECTORY_MSDS_USER_ACCOUNT_DISSABLED, "FALSE"));
            } else {
                mods[1] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(
                        LDAPConstants.ACTIVE_DIRECTORY_USER_ACCOUNT_CONTROL, userAccountControl));
            }
            dirContext.modifyAttributes(compoundName, mods);

        } catch (NamingException e) {
            String errorMessage = "Error while adding the user to the Active Directory for user : " + userName;
            if (isUserBinded) {
                try {
                    dirContext.unbind(compoundName);
                } catch (NamingException e1) {
                    errorMessage = "Error while accessing the Active Directory for user : " + userName;
                    throw new UserStoreException(errorMessage, e);
                }
                errorMessage = "Error while enabling the user account. Please check password policy at DC for user : " +
                               userName;
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            credentialObj.clear();
            JNDIUtil.closeContext(dirContext);
        }
    }

    /**
     * Sets the set of claims provided at adding users
     *
     * @param claims
     * @param basicAttributes
     * @throws UserStoreException
     */
    protected void setUserClaims(Map<String, String> claims, BasicAttributes basicAttributes,
                                 String userName) throws UserStoreException {

        if (logger.isDebugEnabled()) {
            logger.debug("Processing user claims for user : " + userName);
        }

        if (claims != null) {
            BasicAttribute claim;
            Map<String, Object> userStoreProperties = new HashMap<>();

            for (Map.Entry<String, String> entry : claims.entrySet()) {
                // avoid attributes with empty values
                if (EMPTY_ATTRIBUTE_STRING.equals(entry.getValue())) {
                    continue;
                }
                // needs to get attribute name from claim mapping
                String claimURI = entry.getKey();

                // skipping profile configuration attribute
                if (claimURI.equals(UserCoreConstants.PROFILE_CONFIGURATION)) {
                    continue;
                }

                String attributeName = null;

                try {
                    attributeName = getClaimAtrribute(claimURI, userName, null);
                } catch (org.wso2.carbon.user.api.UserStoreException e) {
                    String errorMessage = "Error in obtaining claim mapping.";
                    throw new UserStoreException(errorMessage, e);
                }

                if (StringUtils.isNotEmpty(attributeName)) {
                    userStoreProperties.put(attributeName, entry.getValue());
                }
            }

            processAttributesBeforeUpdate(userStoreProperties);

            for (Map.Entry<String, Object> entry : userStoreProperties.entrySet()) {
                claim = new BasicAttribute(entry.getKey());
                if (entry.getValue() != null) {
                    String claimSeparator = realmConfig.getUserStoreProperty(MULTI_ATTRIBUTE_SEPARATOR);
                    if (claimSeparator != null && !claimSeparator.trim().isEmpty()) {
                        userAttributeSeparator = claimSeparator;
                    }
                    String claimValue = (String) entry.getValue();
                    if (claimValue.contains(userAttributeSeparator)) {
                        StringTokenizer st =
                                new StringTokenizer(claimValue, userAttributeSeparator);
                        while (st.hasMoreElements()) {
                            String newVal = st.nextElement().toString();
                            if (newVal != null && newVal.trim().length() > 0) {
                                claim.add(newVal.trim());
                            }
                        }
                    } else {
                        claim.add(entry.getValue());
                    }
                } else {
                    claim.add(entry.getValue());
                }
                if (logger.isDebugEnabled()) {
                    logger.debug("Attribute name: " + entry.getKey() + " Attribute value: " + entry.getValue());
                }
                basicAttributes.put(claim);
            }
        }
    }

    /**
     *
     */
    public void doUpdateCredential(String userName, Object newCredential, Object oldCredential)
            throws UserStoreException {

        if (!isSSLConnection) {
            logger.warn("Unsecured connection is being used. Password operations will fail");
        }

        DirContext dirContext = this.connectionSource.getContext();
        String searchBase = realmConfig.getUserStoreProperty(LDAPConstants.USER_SEARCH_BASE);
        String searchFilter = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_SEARCH_FILTER);
        searchFilter = searchFilter.replace("?", escapeSpecialCharactersForFilter(userName));

        SearchControls searchControl = new SearchControls();
        String[] returningAttributes = {"CN"};
        searchControl.setReturningAttributes(returningAttributes);
        searchControl.setSearchScope(SearchControls.SUBTREE_SCOPE);
        DirContext subDirContext = null;
        NamingEnumeration<SearchResult> searchResults = null;

        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(newCredential);
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException("Unsupported credential type", e);
        }

        try {
            // search the user with UserNameAttribute and obtain its CN attribute
            searchResults = dirContext.search(escapeDNForSearch(searchBase),
                    searchFilter, searchControl);
            SearchResult user = null;
            int count = 0;
            while (searchResults.hasMore()) {
                if (count > 0) {
                    throw new UserStoreException(
                            "There are more than one result in the user store " + "for user: "
                                    + userName);
                }
                user = searchResults.next();
                count++;
            }
            if (user == null) {
                throw new UserStoreException("User :" + userName + " does not Exist");
            }

            ModificationItem[] mods = null;

            // The user tries to change his own password
            if (oldCredential != null && newCredential != null) {
                mods = new ModificationItem[1];
                mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(
                        LDAPConstants.ACTIVE_DIRECTORY_UNICODE_PASSWORD_ATTRIBUTE,
                        createUnicodePassword(credentialObj)));
            }
            subDirContext = (DirContext) dirContext.lookup(escapeDNForSearch(searchBase));
            subDirContext.modifyAttributes(user.getName(), mods);

        } catch (NamingException e) {
            String error = "Can not access the directory service for user : " + userName;
            if (logger.isDebugEnabled()) {
                logger.debug(error, e);
            }
            throw new UserStoreException(error, e);
        } finally {
            credentialObj.clear();
            JNDIUtil.closeNamingEnumeration(searchResults);
            JNDIUtil.closeContext(subDirContext);
            JNDIUtil.closeContext(dirContext);
        }

    }

    @Override
    public void doUpdateCredentialByAdmin(String userName, Object newCredential)
            throws UserStoreException {
        if (!isSSLConnection) {
            logger.warn("Unsecured connection is being used. Password operations will fail");
        }

        DirContext dirContext = this.connectionSource.getContext();
        String searchBase = realmConfig.getUserStoreProperty(LDAPConstants.USER_SEARCH_BASE);
        String searchFilter = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_SEARCH_FILTER);
        searchFilter = searchFilter.replace("?", escapeSpecialCharactersForFilter(userName));
        SearchControls searchControl = new SearchControls();
        String[] returningAttributes = {"CN"};
        searchControl.setReturningAttributes(returningAttributes);
        searchControl.setSearchScope(SearchControls.SUBTREE_SCOPE);

        DirContext subDirContext = null;
        NamingEnumeration<SearchResult> searchResults = null;
        try {
            // search the user with UserNameAttribute and obtain its CN attribute
            searchResults = dirContext.search(escapeDNForSearch(searchBase), searchFilter, searchControl);
            SearchResult user = null;
            int count = 0;
            while (searchResults.hasMore()) {
                if (count > 0) {
                    throw new UserStoreException("There are more than one result in the user store " + "for user: "
                            + userName);
                }
                user = searchResults.next();
                count++;
            }
            if (user == null) {
                throw new UserStoreException("User :" + userName + " does not Exist");
            }

            ModificationItem[] mods;

            if (newCredential != null) {
                Secret credentialObj;
                try {
                    credentialObj = Secret.getSecret(newCredential);
                } catch (UnsupportedSecretTypeException e) {
                    throw new UserStoreException("Unsupported credential type", e);
                }

                try {
                    mods = new ModificationItem[1];
                    mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(
                            LDAPConstants.ACTIVE_DIRECTORY_UNICODE_PASSWORD_ATTRIBUTE,
                            createUnicodePassword(credentialObj)));

                    subDirContext = (DirContext) dirContext.lookup(escapeDNForSearch(searchBase));
                    subDirContext.modifyAttributes(user.getName(), mods);
                } finally {
                    credentialObj.clear();
                }
            }

        } catch (NamingException e) {
            String error = "Can not access the directory service for user : " + userName;
            if (logger.isDebugEnabled()) {
                logger.debug(error, e);
            }
            throw new UserStoreException(error, e);
        } finally {
            JNDIUtil.closeNamingEnumeration(searchResults);
            JNDIUtil.closeContext(subDirContext);
            JNDIUtil.closeContext(dirContext);
        }
    }

    /**
     *
     */
    protected void doUpdateCredentialsValidityChecks(String userName, Object newCredential)
            throws UserStoreException {
        super.doUpdateCredentialsValidityChecks(userName, newCredential);
        if (!isSSLConnection) {
            logger.warn("Unsecured connection is being used. Password operations will fail");
        }
    }

    /**
     * This is to read and validate the required user store configuration for this user store
     * manager to take decisions.
     *
     * @throws UserStoreException
     */
    protected void checkRequiredUserStoreConfigurations() throws UserStoreException {

        super.checkRequiredUserStoreConfigurations();

        String is_ADLDSRole = realmConfig
                .getUserStoreProperty(LDAPConstants.ACTIVE_DIRECTORY_LDS_ROLE);
        isADLDSRole = Boolean.parseBoolean(is_ADLDSRole);

        if (!isADLDSRole) {
            userAccountControl = realmConfig
                    .getUserStoreProperty(LDAPConstants.ACTIVE_DIRECTORY_USER_ACCOUNT_CONTROL);
            try {
                Integer.parseInt(userAccountControl);
            } catch (NumberFormatException e) {
                userAccountControl = "512";
            }
        }

        String connectionURL = realmConfig.getUserStoreProperty(LDAPConstants.CONNECTION_URL);
        String[] array = connectionURL.split(":");
        boolean startTLSEnabled = Boolean.parseBoolean(
                realmConfig.getUserStoreProperty(UserStoreConfigConstants.STARTTLS_ENABLED));
        if (array[0].equals("ldaps") || startTLSEnabled) {
            this.isSSLConnection = true;
        } else {
            logger.warn("Connection to the Active Directory is not secure. Password involved operations " +
                    "such as update credentials and adduser operations will fail");
        }
    }

    /**
     * Returns password as a UTF_16LE encoded bytes array
     *
     * @param password password instance of Secret
     * @return byte[]
     */
    private byte[] createUnicodePassword(Secret password) {
        char[] passwordChars = password.getChars();
        char[] quotedPasswordChars = new char[passwordChars.length + 2];

        for (int i = 0; i < quotedPasswordChars.length; i++) {
            if (i == 0 || i == quotedPasswordChars.length - 1) {
                quotedPasswordChars[i] = '"';
            } else {
                quotedPasswordChars[i] = passwordChars[i - 1];
            }
        }

        password.setChars(quotedPasswordChars);

        return password.getBytes(StandardCharsets.UTF_16LE);
    }

    /**
     * This method overwrites the method in LDAPUserStoreManager. This implements the functionality
     * of updating user's profile information in LDAP user store.
     *
     * @param userName
     * @param claims
     * @param profileName
     * @throws org.wso2.carbon.user.core.UserStoreException
     */
    @Override
    public void doSetUserClaimValues(String userName, Map<String, String> claims, String profileName)
            throws UserStoreException {
        // get the LDAP Directory context
        DirContext dirContext = this.connectionSource.getContext();
        DirContext subDirContext = null;
        // search the relevant user entry by user name
        String userSearchBase = realmConfig.getUserStoreProperty(LDAPConstants.USER_SEARCH_BASE);
        String userSearchFilter = realmConfig
                .getUserStoreProperty(LDAPConstants.USER_NAME_SEARCH_FILTER);

        if (logger.isDebugEnabled()) {
            logger.debug("Updating user claims of user: " + userName + " in user search base: " + userSearchBase);
        }

        // if user name contains domain name, remove domain name
        String[] userNames = userName.split(CarbonConstants.DOMAIN_SEPARATOR);
        if (userNames.length > 1) {
            userName = userNames[1];
        }
        userSearchFilter = userSearchFilter.replace("?", escapeSpecialCharactersForFilter(userName));

        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setReturningAttributes(null);

        NamingEnumeration<SearchResult> returnedResultList = null;
        String returnedUserEntry = null;

        boolean cnModified = false;
        String cnValue = null;

        try {

            returnedResultList = dirContext.search(escapeDNForSearch(userSearchBase), userSearchFilter, searchControls);
            // assume only one user is returned from the search
            // TODO:what if more than one user is returned
            returnedUserEntry = returnedResultList.next().getName();

        } catch (NamingException e) {
            String errorMessage = "Results could not be retrieved from the directory context for user : " + userName;
            if (logger.isDebugEnabled()) {
                logger.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            JNDIUtil.closeNamingEnumeration(returnedResultList);
        }

        if (profileName == null) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }

        if (claims.get(UserCoreConstants.PROFILE_CONFIGURATION) == null) {
            claims.put(UserCoreConstants.PROFILE_CONFIGURATION,
                    UserCoreConstants.DEFAULT_PROFILE_CONFIGURATION);
        }

        try {
            Attributes updatedAttributes = new BasicAttributes(true);
            Map<String, Object> userStoreProperties = new HashMap<>();

            for (Map.Entry<String, String> claimEntry : claims.entrySet()) {
                userStoreProperties.put(getClaimAtrribute(claimEntry.getKey(), userName, null),
                        claimEntry.getValue());
            }

            processAttributesBeforeUpdate(userStoreProperties);

            for (Map.Entry<String, Object> claimEntry : userStoreProperties.entrySet()) {
                String attributeName = claimEntry.getKey();
                // if there is no attribute for profile configuration in LDAP,
                // skip updating it.
                if (attributeName.equals(UserCoreConstants.PROFILE_CONFIGURATION)) {
                    continue;
                }
                //remove user DN from cache if changing username attribute
                if (realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE).equals
                        (attributeName)) {
                    removeFromUserCache(userName);
                }
                // if mapped attribute is CN, then skip treating as a modified
                // attribute -
                // it should be an object rename
                if ("CN".toLowerCase().equals(attributeName.toLowerCase())) {
                    cnModified = true;
                    cnValue = (String) claimEntry.getValue();
                    continue;
                }
                Attribute currentUpdatedAttribute = new BasicAttribute(attributeName);
				/* if updated attribute value is null, remove its values. */
                if (EMPTY_ATTRIBUTE_STRING.equals((String) claimEntry.getValue())) {
                    currentUpdatedAttribute.clear();
                } else {
                    if (claimEntry.getValue() != null) {
                        String claimSeparator = realmConfig.getUserStoreProperty(MULTI_ATTRIBUTE_SEPARATOR);
                        if (claimSeparator != null && !claimSeparator.trim().isEmpty()) {
                            userAttributeSeparator = claimSeparator;
                        }
                        if (((String) claimEntry.getValue()).contains(userAttributeSeparator)) {
                            StringTokenizer st =
                                    new StringTokenizer((String) claimEntry.getValue(), userAttributeSeparator);
                            while (st.hasMoreElements()) {
                                String newVal = st.nextElement().toString();
                                if (newVal != null && newVal.trim().length() > 0) {
                                    currentUpdatedAttribute.add(newVal.trim());
                                }
                            }
                        } else {
                            currentUpdatedAttribute.add(claimEntry.getValue());
                        }
                    } else {
                        currentUpdatedAttribute.add(claimEntry.getValue());
                    }
                }
                updatedAttributes.put(currentUpdatedAttribute);
            }
            // update the attributes in the relevant entry of the directory
            // store

            subDirContext = (DirContext) dirContext.lookup(escapeDNForSearch(userSearchBase));
            subDirContext.modifyAttributes(returnedUserEntry, DirContext.REPLACE_ATTRIBUTE,
                    updatedAttributes);

            if (cnModified && cnValue != null) {
                subDirContext.rename(returnedUserEntry, "CN=" + escapeSpecialCharactersForDN(cnValue));
            }

        } catch (Exception e) {
            handleException(e, userName);
        } finally {
            JNDIUtil.closeContext(subDirContext);
            JNDIUtil.closeContext(dirContext);
        }

    }

    @Override
    public String[] getUserListOfLDAPRole(RoleContext context, String filter) throws UserStoreException {

        boolean debug = logger.isDebugEnabled();

        if (debug) {
            logger.debug("Getting user list of role: " + context.getRoleName() + " with filter: " + filter);
        }

        List<String> userList = new ArrayList<String>();
        String[] names = new String[0];
        int givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;
        int searchTime = UserCoreConstants.MAX_SEARCH_TIME;

        try {
            givenMax = Integer.parseInt(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;
        }

        try {
            searchTime = Integer.parseInt(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_SEARCH_TIME));
        } catch (Exception e) {
            searchTime = UserCoreConstants.MAX_SEARCH_TIME;
        }

        DirContext dirContext = null;
        NamingEnumeration<SearchResult> answer = null;

        try {
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            searchCtls.setTimeLimit(searchTime);
            searchCtls.setCountLimit(givenMax);

            String groupSearchBase = realmConfig.getUserStoreProperty(LDAPConstants.GROUP_SEARCH_BASE);
            String userListFilter = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_LIST_FILTER);
            String memberOFAttribute = realmConfig.getUserStoreProperty(LDAPConstants.MEMBEROF_ATTRIBUTE);
            String groupNameAttribute = realmConfig.getUserStoreProperty(LDAPConstants.GROUP_NAME_ATTRIBUTE);
            userSearchBase = realmConfig.getUserStoreProperty(LDAPConstants.USER_SEARCH_BASE);
            String searchFilter = "(&" + userListFilter + "(" + memberOFAttribute + "=" + groupNameAttribute + "="
                    + escapeSpecialCharactersForFilter(context.getRoleName()) + "," + groupSearchBase + "))";
            String userNameProperty = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE);
            String displayNameAttribute = realmConfig
                    .getUserStoreProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);
            String returnedAtts[] = {userNameProperty, displayNameAttribute};
            searchCtls.setReturningAttributes(returnedAtts);

            SearchResult sr = null;
            dirContext = connectionSource.getContext();

            answer = dirContext.search(escapeDNForSearch(userSearchBase), searchFilter, searchCtls);

            while (answer.hasMore()) {
                String displayName = null;
                String userName = null;
                sr = answer.next();
                Attributes userAttributes = sr.getAttributes();
                if (userAttributes != null) {
                    Attribute userNameAttribute = userAttributes.get(userNameProperty);
                    if (userNameAttribute != null) {
                        userName = (String) userNameAttribute.get();
                        if (debug) {
                            logger.debug("UserName: " + userName);
                        }
                    }
                    if (StringUtils.isNotEmpty(displayNameAttribute)) {
                        Attribute displayAttribute = userAttributes.get(displayNameAttribute);
                        if (displayAttribute != null) {
                            displayName = (String) displayAttribute.get();
                        }
                        if (debug) {
                            logger.debug("DisplayName: " + displayName);
                        }
                    }

                    String domainName = realmConfig.getUserStoreProperty(
                            UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

                         /*
                         Username will be null in the special case where the
                         username attribute has changed to another
                         and having different userNameProperty than the current
                         user-mgt.xml
                          */
                    if (userName != null) {
                        userName = UserCoreUtil.getCombinedName(domainName, userName, displayName);
                        userList.add(userName);
                        if (debug) {
                            logger.debug(userName + " is added to the result list");
                        }
                    } else {
                        // Skip listing users which are not applicable to current user-mgt.xml.
                        if (debug) {
                            logger.debug("User doesn't have the user name property : " +
                                    userNameProperty);
                        }
                    }
                }
            }

            names = userList.toArray(new String[userList.size()]);

        } catch (PartialResultException e) {
            // Can be due to referrals in AD. so just ignore the error.
            String errorMessage = "Error in reading user information in the user store for filter : " + filter;
            if (isIgnorePartialResultException()) {
                if (debug) {
                    logger.debug(errorMessage, e);
                }
            } else {
                throw new UserStoreException(errorMessage, e);
            }
        } catch (NamingException e) {
            String errorMessage = "Error in reading user information in the user store for filter : " + filter;
            if (debug) {
                logger.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            JNDIUtil.closeNamingEnumeration(answer);
            JNDIUtil.closeContext(dirContext);
        }

        return names;
    }

    @Override
    public void doSetUserClaimValues(String userName, Map<String, List<String>> multiValuedClaimsToAdd,
                                     Map<String, List<String>> multiValuedClaimsToDelete,
                                     Map<String, List<String>> claimsExcludingMultiValuedClaims,
                                     String profileName) throws NotImplementedException {

        throw new NotImplementedException("This functionality is not yet implemented for Active Directory userstores.");

    }

    private boolean isImmutableAttribute(String userName, String claimURI, String value) throws UserStoreException{

        try {
            String attributeName = getClaimAtrribute(claimURI, userName, null);
            Map<String, Object> userStoreAttributeValueMap = new HashMap<>();
            userStoreAttributeValueMap.put(attributeName, value);

            // Exclude the immutable attributes.
            processAttributesBeforeUpdate(userStoreAttributeValueMap);

            // For an immutable attribute the Map is empty.
            if (userStoreAttributeValueMap.isEmpty()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException(
                    "Error occurred while getting the claim attribute for claimURI: " + claimURI + " of the user: "
                            + userName, e);
        }
        return false;
    }

    @Override
    public void doSetUserClaimValue(String userName, String claimURI, String value,
                                    String profileName) throws UserStoreException {

        if (isImmutableAttribute(userName, claimURI, value)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Immutable attribute:" + claimURI + ". Therefore not updating user claim for user: " +
                        userName);
            }
            return;
        }

        // get the LDAP Directory context
        DirContext dirContext = this.connectionSource.getContext();
        DirContext subDirContext = null;
        // search the relevant user entry by user name
        String userSearchBase = realmConfig.getUserStoreProperty(LDAPConstants.USER_SEARCH_BASE);
        String userSearchFilter = realmConfig
                .getUserStoreProperty(LDAPConstants.USER_NAME_SEARCH_FILTER);
        userSearchFilter = userSearchFilter.replace("?", escapeSpecialCharactersForFilter(userName));

        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setReturningAttributes(null);

        NamingEnumeration<SearchResult> returnedResultList = null;
        String returnedUserEntry = null;

        try {

            returnedResultList = dirContext.search(escapeDNForSearch(userSearchBase), userSearchFilter, searchControls);
            // assume only one user is returned from the search
            // TODO:what if more than one user is returned
            returnedUserEntry = returnedResultList.next().getName();
        } catch (NamingException e) {
            String errorMessage = "Results could not be retrieved from the directory context for user : " + userName;
            if (logger.isDebugEnabled()) {
                logger.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            JNDIUtil.closeNamingEnumeration(returnedResultList);
        }

        try {
            Attributes updatedAttributes = new BasicAttributes(true);
            // if there is no attribute for profile configuration in LDAP, skip
            // updating it.
            // get the claimMapping related to this claimURI
            String attributeName = getClaimAtrribute(claimURI, userName, null);

            if ("CN".equals(attributeName)) {
                subDirContext = (DirContext) dirContext.lookup(escapeDNForSearch(userSearchBase));
                subDirContext.rename(returnedUserEntry, "CN=" + value);
                return;
            }

            Attribute currentUpdatedAttribute = new BasicAttribute(attributeName);
			/* if updated attribute value is null, remove its values. */
            if (EMPTY_ATTRIBUTE_STRING.equals(value)) {
                currentUpdatedAttribute.clear();
            } else {
                String claimSeparator = realmConfig.getUserStoreProperty(MULTI_ATTRIBUTE_SEPARATOR);
                if (claimSeparator != null && !claimSeparator.trim().isEmpty()) {
                    userAttributeSeparator = claimSeparator;
                }
                if (value.contains(userAttributeSeparator)) {
                    StringTokenizer st = new StringTokenizer(value, userAttributeSeparator);
                    while (st.hasMoreElements()) {
                        String newVal = st.nextElement().toString();
                        if (newVal != null && newVal.trim().length() > 0) {
                            currentUpdatedAttribute.add(newVal.trim());
                        }
                    }
                } else {
                    currentUpdatedAttribute.add(value);
                }
            }
            updatedAttributes.put(currentUpdatedAttribute);

            // update the attributes in the relevant entry of the directory
            // store

            subDirContext = (DirContext) dirContext.lookup(escapeDNForSearch(userSearchBase));
            subDirContext.modifyAttributes(returnedUserEntry, DirContext.REPLACE_ATTRIBUTE,
                    updatedAttributes);

        } catch (Exception e) {
            handleException(e, userName);
        } finally {
            JNDIUtil.closeContext(subDirContext);
            JNDIUtil.closeContext(dirContext);
        }

    }

    @Override
    public Properties getDefaultUserStoreProperties() {
        Properties properties = new Properties();
        properties.setMandatoryProperties(ActiveDirectoryUserStoreConstants.ACTIVE_DIRECTORY_UM_PROPERTIES.toArray
                (new Property[ActiveDirectoryUserStoreConstants.ACTIVE_DIRECTORY_UM_PROPERTIES.size()]));
        properties.setOptionalProperties(ActiveDirectoryUserStoreConstants.OPTIONAL_ACTIVE_DIRECTORY_UM_PROPERTIES.toArray
                (new Property[ActiveDirectoryUserStoreConstants.OPTIONAL_ACTIVE_DIRECTORY_UM_PROPERTIES.size()]));
        properties.setAdvancedProperties(ACTIVE_DIRECTORY_UM_ADVANCED_PROPERTIES.toArray
                (new Property[ACTIVE_DIRECTORY_UM_ADVANCED_PROPERTIES.size()]));
        return properties;
    }

    private void handleException(Exception e, String userName) throws UserStoreException{
        if (e instanceof InvalidAttributeValueException) {
            String errorMessage = "One or more attribute values provided are incompatible for user : " + userName
                                  + "Please check and try again.";
            if (logger.isDebugEnabled()) {
                logger.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } else if (e instanceof InvalidAttributeIdentifierException) {
            String errorMessage = "One or more attributes you are trying to add/update are not "
                                  + "supported by underlying LDAP for user : " + userName;
            if (logger.isDebugEnabled()) {
                logger.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } else if (e instanceof NoSuchAttributeException) {
            String errorMessage = "One or more attributes you are trying to add/update are not "
                                  + "supported by underlying LDAP for user : " + userName;
            if (logger.isDebugEnabled()) {
                logger.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } else if (e instanceof NamingException) {
            String errorMessage = "Profile information could not be updated in LDAP user store for user : " + userName;
            if (logger.isDebugEnabled()) {
                logger.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } else if (e instanceof org.wso2.carbon.user.api.UserStoreException) {
            String errorMessage = "Error in obtaining claim mapping for user : " + userName;
            if (logger.isDebugEnabled()) {
                logger.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }
    }

    /**
     * Escaping ldap search filter special characters in a string
     * @param dnPartial
     * @return
     */
    private String escapeSpecialCharactersForFilter(String dnPartial){
        boolean replaceEscapeCharacters = true;

        String replaceEscapeCharactersAtUserLoginString = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (logger.isDebugEnabled()) {
                logger.debug("Replace escape characters configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
        }
        //TODO: implement character escaping for *

        if (replaceEscapeCharacters) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < dnPartial.length(); i++) {
                char currentChar = dnPartial.charAt(i);
                switch (currentChar) {
                    case '\\':
                        sb.append("\\5c");
                        break;
//                case '*':
//                    sb.append("\\2a");
//                    break;
                    case '(':
                        sb.append("\\28");
                        break;
                    case ')':
                        sb.append("\\29");
                        break;
                    case '\u0000':
                        sb.append("\\00");
                        break;
                    default:
                        sb.append(currentChar);
                }
            }
            return sb.toString();
        } else {
            return dnPartial;
        }
    }

    /**
     * Escaping ldap DN special characters in a String value
     * @param text
     * @return
     */
    private String escapeSpecialCharactersForDN(String text){
        boolean replaceEscapeCharacters = true;

        String replaceEscapeCharactersAtUserLoginString = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (logger.isDebugEnabled()) {
                logger.debug("Replace escape characters configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
        }

        if(replaceEscapeCharacters) {
            StringBuilder sb = new StringBuilder();
            if ((text.length() > 0) && ((text.charAt(0) == ' ') || (text.charAt(0) == '#'))) {
                sb.append('\\'); // add the leading backslash if needed
            }
            for (int i = 0; i < text.length(); i++) {
                char currentChar = text.charAt(i);
                switch (currentChar) {
                    case '\\':
                        sb.append("\\\\");
                        break;
                    case ',':
                        sb.append("\\,");
                        break;
                    case '+':
                        sb.append("\\+");
                        break;
                    case '"':
                        sb.append("\\\"");
                        break;
                    case '<':
                        sb.append("\\<");
                        break;
                    case '>':
                        sb.append("\\>");
                        break;
                    case ';':
                        sb.append("\\;");
                        break;
                    default:
                        sb.append(currentChar);
                }
            }
            if ((text.length() > 1) && (text.charAt(text.length() - 1) == ' ')) {
                sb.insert(sb.length() - 1, '\\'); // add the trailing backslash if needed
            }
            if (logger.isDebugEnabled()) {
                logger.debug("value after escaping special characters in " + text + " : " + sb.toString());
            }
            return sb.toString();
        } else {
            return text;
        }

    }

    private static void setAdvancedProperties() {
        //Set Advanced Properties

        ACTIVE_DIRECTORY_UM_ADVANCED_PROPERTIES.clear();
        setAdvancedProperty(UserStoreConfigConstants.SCIMEnabled, "Enable SCIM", "false", UserStoreConfigConstants
                .SCIMEnabledDescription);

        setAdvancedProperty(BULK_IMPORT_SUPPORT, "Bulk Import Support", "true", "Bulk Import Supported");
        setAdvancedProperty(UserStoreConfigConstants.emptyRolesAllowed, "Allow Empty Roles", "true", UserStoreConfigConstants
                .emptyRolesAllowedDescription);


        setAdvancedProperty(UserStoreConfigConstants.passwordHashMethod, "Password Hashing Algorithm", "PLAIN_TEXT",
                UserStoreConfigConstants.passwordHashMethodDescription);
        setAdvancedProperty(MULTI_ATTRIBUTE_SEPARATOR, "Multiple Attribute Separator", ",", MULTI_ATTRIBUTE_SEPARATOR_DESCRIPTION);
        setAdvancedProperty("isADLDSRole", "Is ADLDS Role", "false", "Whether an Active Directory Lightweight Directory Services role");
        setAdvancedProperty("userAccountControl", "User Account Control", "512", "Flags that control the behavior of the user account");


        setAdvancedProperty(UserStoreConfigConstants.maxUserNameListLength, "Maximum User List Length", "100", UserStoreConfigConstants
                .maxUserNameListLengthDescription);
        setAdvancedProperty(UserStoreConfigConstants.maxRoleNameListLength, "Maximum Role List Length", "100", UserStoreConfigConstants
                .maxRoleNameListLengthDescription);

        setAdvancedProperty("kdcEnabled", "Enable KDC", "false", "Whether key distribution center enabled");
        setAdvancedProperty("defaultRealmName", "Default Realm Name", "WSO2.ORG", "Default name for the realm");

        setAdvancedProperty(UserStoreConfigConstants.userRolesCacheEnabled, "Enable User Role Cache", "true", UserStoreConfigConstants
                .userRolesCacheEnabledDescription);

        setAdvancedProperty(UserStoreConfigConstants.connectionPoolingEnabled, "Enable LDAP Connection Pooling", "false",
                UserStoreConfigConstants.connectionPoolingEnabledDescription);

        setAdvancedProperty(LDAPConnectionTimeout, "LDAP Connection Timeout", "5000", LDAPConnectionTimeoutDescription);
        setAdvancedProperty(readTimeout, "LDAP Read Timeout", "5000", readTimeoutDescription);
        setAdvancedProperty(RETRY_ATTEMPTS, "Retry Attempts", "0", "Number of retries for" +
                " authentication in case ldap read timed out.");
        setAdvancedProperty("CountRetrieverClass", "Count Implementation", "",
                "Name of the class that implements the count functionality");
        setAdvancedProperty(LDAPConstants.LDAP_ATTRIBUTES_BINARY, "LDAP binary attributes", " ",
                LDAPBinaryAttributesDescription);
        setAdvancedProperty(UserStoreConfigConstants.claimOperationsSupported, UserStoreConfigConstants
                .getClaimOperationsSupportedDisplayName, "true", UserStoreConfigConstants.claimOperationsSupportedDescription);
        setAdvancedProperty(ActiveDirectoryUserStoreConstants.TRANSFORM_OBJECTGUID_TO_UUID,
                ActiveDirectoryUserStoreConstants.TRANSFORM_OBJECTGUID_TO_UUID_DESC , "true",
                ActiveDirectoryUserStoreConstants.TRANSFORM_OBJECTGUID_TO_UUID_DESC);
        setAdvancedProperty(MEMBERSHIP_ATTRIBUTE_RANGE, MEMBERSHIP_ATTRIBUTE_RANGE_DISPLAY_NAME,
                String.valueOf(MEMBERSHIP_ATTRIBUTE_RANGE_VALUE), "Number of maximum users of role returned by the AD");

        setAdvancedProperty(LDAPConstants.USER_CACHE_EXPIRY_MILLISECONDS, USER_CACHE_EXPIRY_TIME_ATTRIBUTE_NAME, "",
                USER_CACHE_EXPIRY_TIME_ATTRIBUTE_DESCRIPTION);
        setAdvancedProperty(LDAPConstants.USER_DN_CACHE_ENABLED, USER_DN_CACHE_ENABLED_ATTRIBUTE_NAME, "true",
                USER_DN_CACHE_ENABLED_ATTRIBUTE_DESCRIPTION);
        setAdvancedProperty(UserStoreConfigConstants.STARTTLS_ENABLED,
                UserStoreConfigConstants.STARTTLS_ENABLED_DISPLAY_NAME, "false",
                UserStoreConfigConstants.STARTTLS_ENABLED_DESCRIPTION);
        setAdvancedProperty(UserStoreConfigConstants.enableMaxUserLimitForSCIM, UserStoreConfigConstants
                        .enableMaxUserLimitDisplayName, "false",
                UserStoreConfigConstants.enableMaxUserLimitForSCIMDescription);
        setAdvancedProperty(UserStoreConfigConstants.immutableAttributes,
                UserStoreConfigConstants.immutableAttributesDisplayName, " ",
                UserStoreConfigConstants.immutableAttributesDescription);
        setAdvancedProperty(UserStoreConfigConstants.timestampAttributes,
                UserStoreConfigConstants.timestampAttributesDisplayName, " ",
                UserStoreConfigConstants.timestampAttributesDescription);
    }


    private static void setAdvancedProperty(String name, String displayName, String value,
                                            String description) {
        Property property = new Property(name, value, displayName + "#" + description, null);
        ACTIVE_DIRECTORY_UM_ADVANCED_PROPERTIES.add(property);

    }

    @Override
    protected void processAttributesBeforeUpdate(Map<String, ? extends Object> userStorePropertyValues) {

        String immutableAttributesProperty = realmConfig
                .getUserStoreProperty(UserStoreConfigConstants.immutableAttributes);

        if (immutableAttributesProperty == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("No immutable attributes found in Active Directory user store");
            }
            return;
        }

        String[] immutableAttributes = StringUtils.split(immutableAttributesProperty, ",");

        if (logger.isDebugEnabled()) {
            logger.debug("Active Directory maintained immutable attributes: " + Arrays.toString(immutableAttributes));
        }

        if (ArrayUtils.isNotEmpty(immutableAttributes)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Updated user store properties before attribute filtering: " + userStorePropertyValues);
            }

            for (String immutableAttribute : immutableAttributes) {
                userStorePropertyValues.remove(immutableAttribute);
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Updated user store properties after attribute filtering: " + userStorePropertyValues);
            }
        }
    }

    @Override
    protected void processAttributesAfterRetrieval(Map<String, String> userStorePropertyValues) {

        String timestampAttributesProperty = realmConfig
                .getUserStoreProperty(UserStoreConfigConstants.timestampAttributes);

        if (timestampAttributesProperty == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("No timestamp attributes found in Active Directory user store.");
            }
            return;
        }

        String[] timestampAttributes = StringUtils.split(timestampAttributesProperty, ",");

        if (logger.isDebugEnabled()) {
            logger.debug("Active Directory timestamp attributes: " + Arrays.toString(timestampAttributes));
        }

        if (ArrayUtils.isNotEmpty(timestampAttributes)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Retrieved user store properties before type conversions: " + userStorePropertyValues);
            }

            for (String timestampAttribute : timestampAttributes) {
                String timestampAttributeValue = userStorePropertyValues.get(timestampAttribute);

                if (StringUtils.isNotEmpty(timestampAttributeValue)) {
                    try {
                        userStorePropertyValues.put(timestampAttribute,
                                convertDateFormatFromAD(timestampAttributeValue));
                    } catch (ParseException e) {
                        logger.error("Error occurred while parsing Active Directory date format for the attribute: "
                               + timestampAttribute + " and value: " + timestampAttributeValue, e);
                    }
                }
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Retrieved user store properties after type conversions: " + userStorePropertyValues);
            }
        }
    }

    private String convertDateFormatFromAD(String fromDate) throws ParseException {

        if (fromDate == null) {
            throw new ParseException("Value provided for date conversion is null.", 0);
        }

        if (scimDateFormat == null) {
            scimDateFormat = new SimpleDateFormat(WSO2_CLAIM_DATE_TIME_FORMAT);
        }

        return scimDateFormat.format(parseGeneralizedTime(fromDate));
    }

    /*
     * Below code snippets were borrowed from Apache LDAP Directory API v2.0.0.
     * As the required Date Time APIs for Active Directory Date format conversion are not available in Java 7.
     * For code comments and further reference,
     * {@See https://github.com/apache/directory-ldap-api/blob/2.0.0/util/src/main/java/
     * org/apache/directory/api/util/GeneralizedTime.java}
     *
     * <code> - Begining snippet of the code borrowed from Apache LDAP API
     */
    private Date parseGeneralizedTime(String generalizedTime) throws ParseException {

        if (calendarForTimestampConversion == null) {
            calendarForTimestampConversion = new GregorianCalendar(TimeZone.getTimeZone("GMT"), Locale.ROOT);
        }

        calendarForTimestampConversion.setTimeInMillis(0);
        calendarForTimestampConversion.setLenient(false);

        parseYear(generalizedTime);
        parseMonth(generalizedTime);
        parseDay(generalizedTime);
        parseHour(generalizedTime);

        if (generalizedTime.length() < 11) {
            throw new ParseException("Bad Generalized Time.", 10);
        }

        int positionOfElement = 10;
        char charAtPositionOfElement = generalizedTime.charAt(positionOfElement);

        if (('0' <= charAtPositionOfElement) && (charAtPositionOfElement <= '9')) {
            parseMinute(generalizedTime);

            if (generalizedTime.length() < 13) {
                throw new ParseException("Bad Generalized Time.", 12);
            }

            positionOfElement = 12;
            charAtPositionOfElement = generalizedTime.charAt(positionOfElement);

            if (('0' <= charAtPositionOfElement) && (charAtPositionOfElement <= '9')) {
                parseSecond(generalizedTime);

                if (generalizedTime.length() < 15) {
                    throw new ParseException("Bad Generalized Time.", 14);
                }

                positionOfElement = 14;
                charAtPositionOfElement = generalizedTime.charAt(positionOfElement);

                if ((charAtPositionOfElement == '.') || (charAtPositionOfElement == ',')) {
                    parseFractionOfSecond(generalizedTime);
                    positionOfElement += 1;
                    parseTimezone(generalizedTime, positionOfElement);
                } else if ((charAtPositionOfElement == 'Z') || (charAtPositionOfElement == '+')
                        || (charAtPositionOfElement == '-')) {
                    parseTimezone(generalizedTime, positionOfElement);
                } else {
                    throw new ParseException("Time is too short.", 14);
                }
            } else if ((charAtPositionOfElement == '.') || (charAtPositionOfElement == ',')) {
                parseFractionOfMinute(generalizedTime);
                positionOfElement += 1;

                parseTimezone(generalizedTime, positionOfElement);
            } else if ((charAtPositionOfElement == 'Z') || (charAtPositionOfElement == '+')
                    || (charAtPositionOfElement == '-')) {
                parseTimezone(generalizedTime, positionOfElement);
            } else {
                throw new ParseException("Time is too short.", 12);
            }
        } else if ((charAtPositionOfElement == '.') || (charAtPositionOfElement == ',')) {
            parseFractionOfHour(generalizedTime);
            positionOfElement += 1;

            parseTimezone(generalizedTime, positionOfElement);
        } else if ((charAtPositionOfElement == 'Z') || (charAtPositionOfElement == '+')
                || (charAtPositionOfElement == '-')) {
            parseTimezone(generalizedTime, positionOfElement);
        } else {
            throw new ParseException("Invalid Generalized Time.", 10);
        }

        try {
            calendarForTimestampConversion.getTimeInMillis();
        } catch (IllegalArgumentException iae) {
            throw new ParseException("Invalid date time.", 0);
        }

        calendarForTimestampConversion.setLenient(true);
        return calendarForTimestampConversion.getTime();
    }

    private void parseTimezone(String generalizedTime, int positionOfElement) throws ParseException {

        if (generalizedTime.length() < positionOfElement + 1) {
            throw new ParseException("Time is too short, no 'timezone' element found.", positionOfElement);
        }

        char charAtPositionOfElement = generalizedTime.charAt(positionOfElement);

        if (charAtPositionOfElement == 'Z') {
            calendarForTimestampConversion.setTimeZone(TimeZone.getTimeZone("GMT"));

            if (generalizedTime.length() > positionOfElement + 1) {
                throw new ParseException("Time is too short, no 'timezone' element found.", positionOfElement + 1);
            }
        } else if ((charAtPositionOfElement == '+') || (charAtPositionOfElement == '-')) {
            StringBuilder stringBuilder = new StringBuilder("GMT");
            stringBuilder.append(charAtPositionOfElement);

            String digits = getAllDigits(generalizedTime, positionOfElement + 1);
            stringBuilder.append(digits);

            if (digits.length() == 2 && digits.matches("^([01]\\d|2[0-3])$")) {
                TimeZone timeZone = TimeZone.getTimeZone(stringBuilder.toString());
                calendarForTimestampConversion.setTimeZone(timeZone);
            } else if (digits.length() == 4 && digits.matches("^([01]\\d|2[0-3])([0-5]\\d)$")) {
                TimeZone timeZone = TimeZone.getTimeZone(stringBuilder.toString());
                calendarForTimestampConversion.setTimeZone(timeZone);
            } else {
                throw new ParseException("Value of 'timezone' must be 2 digits or 4 digits.", positionOfElement);
            }

            if (generalizedTime.length() > positionOfElement + 1 + digits.length()) {
                throw new ParseException("Time is too short, no 'timezone' element found.",
                        positionOfElement + 1 + digits.length());
            }
        }
    }

    private void parseFractionOfSecond(String fromDate) throws ParseException {

        String fraction = getFraction(fromDate, 14 + 1);
        double fractionDouble = Double.parseDouble("0." + fraction);
        int millisecond = (int) Math.floor(fractionDouble * 1000);

        calendarForTimestampConversion.set(GregorianCalendar.MILLISECOND, millisecond);
    }

    private void parseFractionOfMinute(String generalizedTime) throws ParseException {

        String fraction = getFraction(generalizedTime, 12 + 1);
        double fractionDouble = Double.parseDouble("0." + fraction);
        int milliseconds = (int) Math.round(fractionDouble * 1000 * 60);
        int second = milliseconds / 1000;
        int millisecond = milliseconds - (second * 1000);

        calendarForTimestampConversion.set(Calendar.SECOND, second);
        calendarForTimestampConversion.set(Calendar.MILLISECOND, millisecond);
    }

    private void parseFractionOfHour(String generalizedTime) throws ParseException {

        String fraction = getFraction(generalizedTime, 10 + 1);
        double fractionDouble = Double.parseDouble("0." + fraction);
        int milliseconds = (int) Math.round(fractionDouble * 1000 * 60 * 60);
        int minute = milliseconds / (1000 * 60);
        int second = (milliseconds - (minute * 60 * 1000)) / 1000;
        int millisecond = milliseconds - (minute * 60 * 1000) - (second * 1000);

        calendarForTimestampConversion.set(Calendar.MINUTE, minute);
        calendarForTimestampConversion.set(Calendar.SECOND, second);
        calendarForTimestampConversion.set(Calendar.MILLISECOND, millisecond);
    }

    private String getAllDigits(String generalizedTime, int startIndex) {

        StringBuilder stringBuilder = new StringBuilder();
        while (generalizedTime.length() > startIndex) {
            char charAtStartIndex = generalizedTime.charAt(startIndex);
            if ('0' <= charAtStartIndex && charAtStartIndex <= '9') {
                stringBuilder.append(charAtStartIndex);
                startIndex++;
            } else {
                break;
            }
        }
        return stringBuilder.toString();
    }

    private void parseSecond(String generalizedTime) throws ParseException {

        if (generalizedTime.length() < 14) {
            throw new ParseException("Time is too short, no 'second' element found.", 12);
        }
        try {
            int second = Integer.parseInt(generalizedTime.substring(12, 14));
            calendarForTimestampConversion.set(Calendar.SECOND, second);
        } catch (NumberFormatException e) {
            throw new ParseException("Value of 'second' is not a number.", 12);
        }
    }

    private void parseMinute(String generalizedTime) throws ParseException {

        if (generalizedTime.length() < 12) {
            throw new ParseException("Time is too short, no 'minute' element found.", 10);
        }
        try {
            int minute = Integer.parseInt(generalizedTime.substring(10, 12));
            calendarForTimestampConversion.set(Calendar.MINUTE, minute);
        } catch (NumberFormatException e) {
            throw new ParseException("Value of 'minute' is not a number.", 10);
        }
    }

    private void parseHour(String generalizedTime) throws ParseException {

        if (generalizedTime.length() < 10) {
            throw new ParseException("Time is too short, no 'hour' element found.", 8);
        }
        try {
            int hour = Integer.parseInt(generalizedTime.substring(8, 10));
            calendarForTimestampConversion.set(Calendar.HOUR_OF_DAY, hour);
        } catch (NumberFormatException e) {
            throw new ParseException("Value of 'hour' is not a number.", 8);
        }
    }

    private void parseDay(String generalizedTime) throws ParseException {

        if (generalizedTime.length() < 8) {
            throw new ParseException("Time is too short, no 'day' element found.", 6);
        }
        try {
            int day = Integer.parseInt(generalizedTime.substring(6, 8));
            calendarForTimestampConversion.set(Calendar.DAY_OF_MONTH, day);
        } catch (NumberFormatException e) {
            throw new ParseException("Value of 'day' is not a number.", 6);
        }
    }

    private void parseMonth(String generalizedTime) throws ParseException {

        if (generalizedTime.length() < 6) {
            throw new ParseException("Time is too short, no 'month' element found.", 4);
        }
        try {
            int month = Integer.parseInt(generalizedTime.substring(4, 6));
            calendarForTimestampConversion.set(Calendar.MONTH, month - 1);
        } catch (NumberFormatException e) {
            throw new ParseException("Value of 'month' is not a number.", 4);
        }
    }

    private void parseYear(String generalizedTime) throws ParseException {

        if (generalizedTime.length() < 4) {
            throw new ParseException("Time is too short, no 'year' element found.", 0);
        }
        try {
            int year = Integer.parseInt(generalizedTime.substring(0, 4));
            calendarForTimestampConversion.set(Calendar.YEAR, year);
        } catch (NumberFormatException e) {
            throw new ParseException("Value of 'year' is not a number.", 0);
        }
    }

    private String getFraction(String generalizedTime, int startIndex) throws ParseException {

        String fraction = getAllDigits(generalizedTime, startIndex);

        if (fraction.length() == 0) {
            throw new ParseException("Time is too short, no 'fraction' element found.", startIndex);
        }

        return fraction;
    }
    /* </code> - Ending snippet of the code borrowed from Apache LDAP API */

}
