/*
*  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/
package org.wso2.carbon.user.core.hybrid;

import org.apache.commons.dbcp.BasicDataSource;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.BaseTestCase;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserCoreTestConstants;
import org.wso2.carbon.user.core.common.DefaultRealm;
import org.wso2.carbon.user.core.config.TestRealmConfigBuilder;
import org.wso2.carbon.user.core.jdbc.JDBCRealmTest;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.dbcreator.DatabaseCreator;

import java.io.File;
import java.io.InputStream;

public class HybridRoleManagerTest extends BaseTestCase {

    private HybridRoleManager hybridRoleMan;
    private HybridRoleManager hybridRoleManLDAP;

    public void setUp() throws Exception {
        super.setUp();
    }

    public void testHybridRoleManager() throws Exception {
        initTestPreRequisites();
        initTestPreRequisitesForLDAP();
        doHybridRoleTesting();
        doHybridRoleTestingForLDAP();
    }

    private void initTestPreRequisites() throws Exception {

        String dbFolder = "target/hybridroletest";
        String TEST_URL = "jdbc:h2:./target/HybridRoleTest/CARBON_TEST";

        if ((new File(dbFolder)).exists()) {
            deleteDir(new File(dbFolder));
        }

        BasicDataSource ds = new BasicDataSource();
        ds.setDriverClassName(UserCoreTestConstants.DB_DRIVER);
        ds.setUrl(TEST_URL);

        DatabaseCreator creator = new DatabaseCreator(ds);
        creator.createRegistryDatabase();
        // taking the tenant id = 0
        DefaultRealm realm = new DefaultRealm();
        InputStream inStream = this.getClass().getClassLoader().getResource(JDBCRealmTest.JDBC_TEST_USERMGT_XML).openStream();
        RealmConfiguration realmConfig = TestRealmConfigBuilder
                .buildRealmConfigWithJDBCConnectionUrl(inStream, TEST_URL);
        hybridRoleMan = new HybridRoleManager(ds, 0, realmConfig, realm);

        // Adding primary domain
        UserCoreUtil.persistDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME, 0, ds);
    }

    private void initTestPreRequisitesForLDAP() throws Exception {

        String dbFolder = "target/hybridroletest";
        String TEST_URL = "jdbc:h2:./target/HybridRoleTest/CARBON_TEST";

        if ((new File(dbFolder)).exists()) {
            deleteDir(new File(dbFolder));
        }

        BasicDataSource ds = new BasicDataSource();
        ds.setDriverClassName(UserCoreTestConstants.DB_DRIVER);
        ds.setUrl(TEST_URL);

        DatabaseCreator creator = new DatabaseCreator(ds);
        creator.createRegistryDatabase();
        // taking the tenant id = 0
        DefaultRealm realm = new DefaultRealm();
        InputStream inStream = this.getClass().getClassLoader().getResource("ldap-user-mgt-test.xml").openStream();
        RealmConfiguration realmConfig = TestRealmConfigBuilder
                .buildRealmConfigWithJDBCConnectionUrl(inStream, TEST_URL);
        hybridRoleManLDAP = new HybridRoleManager(ds, 0, realmConfig, realm);

        // Adding primary domain
        UserCoreUtil.persistDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME, 0, ds);
    }

    private void doHybridRoleTesting() throws Exception {
        String role_1 = "ThunderCats";
        String role_2 = "Siblings";
        String role_3 = "Application/user002100000001 ";

        hybridRoleMan.addHybridRole(role_1, new String[] { "Lionel", "Chitarah", "Willykat", "Willykit" });
        assertTrue(hybridRoleMan.isExistingRole(role_1));

        hybridRoleMan.addHybridRole(role_2, new String[] { "Willykat", "Willykit" });
        assertEquals(2, hybridRoleMan.getHybridRoles("*").length);
        assertEquals(4, hybridRoleMan.getUserListOfHybridRole(role_1).length);
        assertTrue(hybridRoleMan.isUserInRole("Willykat", role_2));

        hybridRoleMan.addHybridRole(role_3, new String[] {"admin"});
        assertTrue(hybridRoleMan.isUserInRole("admin", role_3));
    }

    private void doHybridRoleTestingForLDAP() throws Exception {
        String role_1 = "subscriber";
        String role_2 = "publisher";

        //add role_1 to user "abc"
        hybridRoleManLDAP.addHybridRole(role_1, new String[]{"abc"});
        assertTrue(hybridRoleManLDAP.isExistingRole(role_1));
        //update the user roles of user "abc"
        hybridRoleManLDAP.updateHybridRoleListOfUser("abc", new String[]{}, new String[]{role_1});
        assertTrue(hybridRoleManLDAP.isExistingRole(role_1));
        //Check whether the role_1 is assigned for both user "abc" and "ABC"
        assertTrue(hybridRoleManLDAP.isUserInRole("abc", role_1));
        assertTrue(hybridRoleManLDAP.isUserInRole("ABC", role_1));

        //add role_2 to user "abc"
        hybridRoleManLDAP.addHybridRole(role_2, new String[]{"abc"});
        assertTrue(hybridRoleManLDAP.isExistingRole(role_2));
        assertTrue(hybridRoleManLDAP.isUserInRole("abc", role_2));
        assertTrue(hybridRoleManLDAP.isUserInRole("ABC", role_2));
        //delete role_2 from user "ABC"
        hybridRoleManLDAP.updateHybridRoleListOfUser("ABC", new String[]{role_2}, new String[]{});
        assertTrue(hybridRoleManLDAP.isExistingRole(role_2));
        //check whether the role_2 is deleted from both user "abc" and "ABC"
        assertFalse(hybridRoleManLDAP.isUserInRole("abc", role_2));
        assertFalse(hybridRoleManLDAP.isUserInRole("ABC", role_2));
    }
}
