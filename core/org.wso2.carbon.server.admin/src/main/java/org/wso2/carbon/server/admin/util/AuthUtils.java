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
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.carbon.base.ServerConfiguration;

/**
 * Util class for the user authentication and authorization related operations.
 */
public class AuthUtils {

    private static final Log log = LogFactory.getLog(AuthUtils.class);

    private static final String DISABLE_AUTHORIZATION_PROPERTY = "DisableAuthorizationForSoapService";
    private static final String SERVICE_PROPERTY = "Service";
    private static final String SERVICE_NAME = "name";
    private static final String AUTHORIZATION_DECISION = "disable";

    /**
     * Reads the configuration to decide whether the authorization is disabled for the service.
     *
     * @param msgContext {@link MessageContext} of the service call
     * @return the boolean value of the decision
     */
    public static boolean isAuthorizationDisabled(MessageContext msgContext) {

        NodeList serviceNodeCandidates = ServerConfiguration.getInstance().getDocumentElement()
                .getElementsByTagName(DISABLE_AUTHORIZATION_PROPERTY);

        if (serviceNodeCandidates != null && serviceNodeCandidates.item(0) != null) {

            NodeList childNodes = serviceNodeCandidates.item(0).getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {

                Node childElement = childNodes.item(i);
                if (childElement.getNodeType() == Node.ELEMENT_NODE && SERVICE_PROPERTY
                        .equals(childElement.getNodeName())) {

                    NamedNodeMap attributes = childElement.getAttributes();
                    String serviceName = attributes.getNamedItem(SERVICE_NAME).getTextContent();

                    if (StringUtils.equals(serviceName, msgContext.getAxisService().getName())) {
                        boolean isDisabled =
                                Boolean.parseBoolean(attributes.getNamedItem(AUTHORIZATION_DECISION).getTextContent());
                        if (isDisabled) {
                            log.info("Service " + serviceName + " has been configured to disable authorization " +
                                    "with the property DisableAuthorizationForSoapService at carbon.xml.");
                        }
                        return isDisabled;
                    }
                }
            }
        }
        return false;
    }
}
