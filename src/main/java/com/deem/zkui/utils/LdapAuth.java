/**
 * Copyright (c) 2014, Deem Inc. All Rights Reserved.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.deem.zkui.utils;

import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.Hashtable;

public class LdapAuth {

    DirContext ctx = null;
    private final static org.slf4j.Logger logger = LoggerFactory.getLogger(LdapAuth.class);

    /**
     * @param ldapUrl
     * @param baseUserGroupDn e.g.: "ou=user,dc=ips,dc=com"
     * @param username
     * @param password
     * @return
     * @throws NamingException
     */
    public DirContext authenticateUser(String ldapUrl, String baseUserGroupDn, String username, String password) throws NamingException {
        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "uid=" + username + "," + baseUserGroupDn);
        env.put(Context.SECURITY_CREDENTIALS, password);
        ctx = new InitialDirContext(env);
        return ctx;
    }


    /**
     * 获取认证用户姓名CN
     *
     * @param ctx
     * @param baseUserGroupDn
     * @param username
     * @return
     * @throws NamingException
     */
    public String getAuthenticatedUserCn(DirContext ctx, String baseUserGroupDn, String username) throws NamingException {
        String searchFilter = "(uid=" + username + ")";
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> results = ctx.search(baseUserGroupDn, searchFilter, searchControls);
        while (results.hasMoreElements()) {
            Attribute userCnAttribute = results.next().getAttributes().get("cn");
            return userCnAttribute == null ? null : (String)userCnAttribute.get();
        }
        return null;
    }

}
