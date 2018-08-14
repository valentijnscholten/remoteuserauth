/**
 * Copyright 2016 Angus Warren
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

package anguswarren.confluence;

import java.io.InputStream;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Category;

import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.core.util.ClassLoaderUtils;
import com.atlassian.user.User;
import com.atlassian.user.search.page.Pager;

public class RemoteUserConfluenceAuth extends ConfluenceAuthenticator {

	private static final long serialVersionUID = 1L;
	private static final Category log = Category.getInstance(RemoteUserConfluenceAuth.class);

	private static Properties props;

	private Properties getProperties() {
		if (props == null) {
			props = new Properties();
			try {
				InputStream iStream = ClassLoaderUtils.getResourceAsStream("RemoteUserConfluenceAuth.properties", this.getClass());
				props.load(iStream);
				log.info("loaded properties file: "+  props);
			} catch (Exception e) {
				log.warn("Exception loading properties. The properties file is optional anyway, so this may not be an issues: " + e, e);
			}
			if (props == null) {

			}
			String trustedhosts = props.getProperty("trustedhosts");
			if (trustedhosts == null) {
				log.warn("trustedhosts not configured, defaulting to allow only headers from 127.0.0.1.");
				props.setProperty("trustedhosts", "127.0.0.1");
			}
		}
		return props;
	}

    @Override
	public Principal getUser(HttpServletRequest request, HttpServletResponse response) {
        Principal user = null;
        try {
            if (request.getSession() != null && request.getSession().getAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY) != null) {
                log.debug("Session found; user already logged in");
                user = (Principal) request.getSession().getAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY);
                String username = user.getName();
                user = getUser(username);
            } else {
                String ipAddress = request.getRemoteAddr();
                log.debug("remote ip address: " + ipAddress);
                String trustedhosts = getProperties().getProperty("trustedhosts");
                if (trustedhosts != null) {
                    if (Arrays.asList(trustedhosts.split(",")).contains(ipAddress)) {
                        log.debug("IP found in trustedhosts.");
                    } else {
                        log.warn("IP '" + ipAddress + "' not found in trustedhosts: ");
                        return null;
                    }
                } else {
                    //should never happen
                	log.warn("trustedhosts not configured. If you're using http headers, this may be a security issue. Dropping request");
                	return null;
                }

                String remoteuser = null;
                String header = getProperties().getProperty("header");
                if (header == null) {
                    //remoteuser = request.getRemoteUser();
                	//query header directly, because getRemoteUser() will return null when not using any authentication built into Tomcat
                	remoteuser = request.getHeader("REMOTE_USER");
                    log.debug("Trying REMOTE_USER for SSO: " + remoteuser);
                } else {
                    remoteuser = request.getHeader(header);
                    log.debug("Trying HTTP header '" + header + "' for SSO: " + remoteuser);
                }

                log.debug("Request headers: ");
                for (String name: Collections.list(request.getHeaderNames())) {
                	log.debug(name + "=" + request.getHeader(name));
                }

                if (remoteuser != null) {
//                    String[] username = remoteuser.split("@");
//                    user = getUser(username[0]);

                	Pager<User> usersByEmail = getUserAccessor().getUsersByEmail(remoteuser).pager();
                	if (usersByEmail.isEmpty()) {
                		log.info("email address not found: " + remoteuser + " login failed");
                		return null;
                	}

                	int count = 0;
                	for (User userByEmail: usersByEmail) {
                		user = userByEmail;
                		if (count > 0) {
                    		log.info("email address not unique: " + remoteuser + " login failed");
                    		return null;
                		}
                		count = count + 1;
                	}

                	//we only get here if there's an exact match, so 1 user found with this email

                    log.debug("Logging in with username: " + user);
                    request.getSession().setAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY, user);
                    request.getSession().setAttribute(ConfluenceAuthenticator.LOGGED_OUT_KEY, null);
                } else {
                    log.debug("remote_user is null");
                    return null;
                }
            }
        } catch (Exception e) {
            log.error("Exception: " + e, e);
        }
        return user;
    }
}
