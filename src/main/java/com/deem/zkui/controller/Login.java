/**
 *
 * Copyright (c) 2014, Deem Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */
package com.deem.zkui.controller;

import freemarker.template.TemplateException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.deem.zkui.utils.ServletUtil;
import com.deem.zkui.utils.ZooKeeperUtil;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.deem.zkui.utils.LdapAuth;
import java.util.Arrays;

/**
 * modify by caobin - ldap enhancement
 */
@SuppressWarnings("serial")
@WebServlet(urlPatterns = {"/login"})
public class Login extends HttpServlet {

    private final static Logger logger = LoggerFactory.getLogger(Login.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.debug("Login Action!");
        try {
            Properties globalProps = (Properties) getServletContext().getAttribute("globalProps");
            Map<String, Object> templateParam = new HashMap<>();
            templateParam.put("uptime", globalProps.getProperty("uptime"));
            templateParam.put("loginMessage", globalProps.getProperty("loginMessage"));
            ServletUtil.INSTANCE.renderHtml(request, response, templateParam, "login.ftl.html");
        } catch (TemplateException ex) {
            logger.error(Arrays.toString(ex.getStackTrace()));
            ServletUtil.INSTANCE.renderError(request, response, ex.getMessage());
        }

    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.debug("Login Post Action!");
        try {
            Properties globalProps = (Properties) getServletContext().getAttribute("globalProps");
            Map<String, Object> templateParam = new HashMap<>();
            HttpSession session = request.getSession(true);
            session.setMaxInactiveInterval(Integer.valueOf(globalProps.getProperty("sessionTimeout")));
            //TODO: Implement custom authentication logic if required.
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            String role = null;
            Boolean authenticated = false;
            if (globalProps.getProperty("ldapAuth").equals("true")) {
                authenticated = true;
                LdapAuth ldapAuth = new LdapAuth();
                DirContext ctx = ldapAuth.authenticateUser(globalProps.getProperty("ldapUrl"), globalProps.getProperty("ldapUserGroupDn"), username, password);
                if (ctx != null) {
                    try {
                        String searchFilter = globalProps.getProperty("ldapRoleGroupSearchFilter");
                        SearchControls searchControls = new SearchControls();
                        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                        NamingEnumeration<SearchResult> results = ctx.search(globalProps.getProperty("ldapRoleGroupDn"), searchFilter, searchControls);
                        while (results.hasMoreElements()) {
                            SearchResult searchResult = results.nextElement();
                            Attribute memberAttribute = searchResult.getAttributes().get("member");
                            if(memberAttribute != null
                                    && (memberAttribute.contains("uid=" + username + "," + globalProps.getProperty("ldapUserGroupDn")))){
                                Attribute roleAttribute = searchResult.getAttributes().get("cn");
                                if(roleAttribute != null){
                                    username = ldapAuth.getAuthenticatedUserCn(ctx, globalProps.getProperty("ldapUserGroupDn"), username);
                                    role = (String)roleAttribute.get();
                                    break;
                                }
                            }else{
                                continue;
                            }
                        }
                    }finally {
                        if(ctx != null){
                            ctx.close();
                        }
                    }

                    if (role == null) {
                        //role = ZooKeeperUtil.ROLE_USER;
                        authenticated = false;
                    }

                }
            } else {
                JSONArray jsonRoleSet = (JSONArray) ((JSONObject) new JSONParser().parse(globalProps.getProperty("userSet"))).get("users");
                for (Iterator it = jsonRoleSet.iterator(); it.hasNext();) {
                    JSONObject jsonUser = (JSONObject) it.next();
                    if (jsonUser.get("username").equals(username) && jsonUser.get("password").equals(password)) {
                        authenticated = true;
                        role = (String) jsonUser.get("role");
                    }
                }
            }
            if (authenticated) {
                logger.info("Login successful: " + username);
                session.setAttribute("authName", username);
                session.setAttribute("authRole", role);
                response.sendRedirect("/home");
            } else {
                session.setAttribute("flashMsg", "Invalid Login");
                ServletUtil.INSTANCE.renderHtml(request, response, templateParam, "login.ftl.html");
            }

        } catch (ParseException | TemplateException | NamingException ex) {
            logger.error(Arrays.toString(ex.getStackTrace()));
            ServletUtil.INSTANCE.renderError(request, response, ex.getMessage());
        }
    }
}
