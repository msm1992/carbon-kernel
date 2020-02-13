/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.server.admin.util;

import org.apache.axis2.context.MessageContext;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.ServerConfiguration;

/**
 * Util class for the user authentication and authorization related operations.
 */
public class AuthUtils {

    private static final Log log = LogFactory.getLog(AuthUtils.class);

    private static final String DISABLE_AUTHORIZATION_PROPERTY = "DisableAuthorizationForSoapServices.Service";

    /**
     * Reads the configuration to decide whether the authorization is disabled for the service.
     *
     * @param msgContext {@link MessageContext} of the service call
     * @return the boolean value of the decision
     */
    public static boolean isAuthorizationDisabled(MessageContext msgContext) {

        String[] serviceNames = ServerConfiguration.getInstance().getProperties(DISABLE_AUTHORIZATION_PROPERTY);

        for (String serviceName : serviceNames) {
            if (StringUtils.equals(serviceName, msgContext.getAxisService().getName())) {
                if (log.isDebugEnabled()) {
                    log.debug("Service " + serviceName + " has been configured to disable authorization " +
                            "under DisableAuthorizationForSoapServices at carbon.xml.");
                }
                return true;
            }
        }
        return false;
    }
}
