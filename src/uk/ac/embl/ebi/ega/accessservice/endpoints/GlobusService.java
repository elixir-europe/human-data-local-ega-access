/*
 * Copyright 2015 EMBL-EBI.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uk.ac.embl.ebi.ega.accessservice.endpoints;

import io.buji.pac4j.ClientToken;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpResponseStatus;
import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http.HttpResponseStatus.SEE_OTHER;
import static io.netty.handler.codec.http.HttpResponseStatus.UNAUTHORIZED;
import java.util.ArrayList;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.pac4j.oauth.credentials.OAuthCredentials;
import org.slf4j.LoggerFactory;
import uk.ac.embl.ebi.ega.accessservice.EgaSecureAccessService;
import uk.ac.embl.ebi.ega.accessservice.utils.SigVer;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;

public class GlobusService extends ServiceTemplate implements Service {
    
    private static final transient org.slf4j.Logger log = LoggerFactory.getLogger(GlobusService.class);

    @Override
    public JSONObject handle(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, SigVer sig, EgaSecureAccessService ref) {
        JSONObject json = new JSONObject(); // Start out with common JSON Object
    
        // /globus/new/
        // /globus/{user}/
        
        try {
            boolean verified = false;
            String[] result = null;                         // Holds Token results
            String clientIP = parameters.get("ip");         // Needed to pick correct key for signature validation
System.out.println("clientIP: " + clientIP);
            String function = id.get(0);                    // globus
System.out.println("function: " + function);
            HttpResponseStatus status = null;
            if (!function.equalsIgnoreCase("globus")) {
                status = NOT_FOUND; // URL incorrect
                json.put("header", responseHeader(status)); // Header Section of the response
                return json;
            }
            String sub_function = id.size()>1?id.get(1):""; // new or user
System.out.println("sub_function: " + sub_function);
            
            // There must be a valid oAuth 2.0 token
            HttpHeaders headers = request.headers();
            String oAuth_Token = headers.get("Authorization").toString();
System.out.println("token.. " + oAuth_Token);

            result = new String[]{authenticateUser(sub_function, oAuth_Token)};
            //result = new String[]{EgaSecureAccessService.getUserID(user)}; // v1 code
            //result = new String[]{"success"};
            if (result[0].equalsIgnoreCase("null")) result[0] = "false";

            if (result!=null && result.length>0 && result[0].toLowerCase().startsWith("success")) {
                json.put("header", responseHeader(OK)); // Header Section of the response
            } else {
                json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                //result = new String[]{"false"};
            }
            
            json.put("response", responseSection(result));            
            
        } catch (JSONException ex) {
            try {
                json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
            } catch (JSONException ex1) {
                Logger.getLogger(StatService.class.getName()).log(Level.SEVERE, null, ex1);
            }
            Logger.getLogger(GlobusService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(GlobusService.class.getName()).log(Level.SEVERE, null, ex);
        }

        return json;
    }

    // Authenticate user (email) against database by comparing Hash values
    private String authenticateUser(String user, String oauth_token) {
        ensureUserIsLoggedOut();
        Subject currentUser = SecurityUtils.getSubject();
System.out.println("user " + (currentUser!=null) );

        // Check users - if different user, log out current user
        try {
            System.out.println(" - - " + (currentUser!= null));
            
            if (currentUser!= null) {
                if (currentUser.getPrincipal()!=null) {
                    if (user.equalsIgnoreCase(currentUser.getPrincipal().toString())) {
                        currentUser.logout();
                        //logoutUser();
                    }
                }
            } else {
                System.out.println("NULL User??");
            }
        } catch (Throwable ex) {
            System.out.println(" --- " + ex.getLocalizedMessage());
        }
        
        // Perform login
        String text = "";
        if (currentUser!=null && !currentUser.isAuthenticated()) {
            
            String cUser = currentUser.getPrincipal().toString();
            OAuthCredentials x = new OAuthCredentials(oauth_token, cUser); // oAuth token
            
            ClientToken token = new ClientToken(cUser, x);            
            token.setRememberMe(false);
            try {
                currentUser.login(token);
                text = "Success: " + token.getPrincipal();
System.out.println("text: " + text);
                log.info(text);
            } catch (UnknownAccountException uae) {
                text = "There is no user with username of " + token.getPrincipal();
                log.info(text);
            } catch (IncorrectCredentialsException ice) {
                text = "Password for account " + token.getPrincipal() + " was incorrect!";
                log.info(text);
            } catch (LockedAccountException lae) {
                text = "The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.";
                log.info(text);
            }
            // ... catch more exceptions here (maybe custom ones specific to your application?
            catch (AuthenticationException ae) {
                //unexpected condition?  error?
                System.out.println(" ->> ");
                System.out.println(text);
                System.out.println(ae.getLocalizedMessage());
            }
            catch (Throwable th) {
            System.out.println(" --> " + th.getLocalizedMessage());
            }
        }
        
        try {
            Session session = currentUser.getSession();
            System.out.println(session.getHost());
            System.out.println(session.getId());
            System.out.println(session.getLastAccessTime().toLocaleString());
            if (currentUser.getPrincipal()!=null) System.out.println(currentUser.getPrincipal().toString());
        } catch (Throwable th) {}
        
        //return (currentUser!=null && currentUser.isAuthenticated());
        return text;
    }
    
    // Clean way to get the subject
    private Subject getSubject()
    {
        Subject currentUser = SecurityUtils.getSubject();// SecurityUtils.getSubject();

        if (currentUser == null)
        {
            currentUser = SecurityUtils.getSubject();
        }

        return currentUser;
    }

    // Logout the user fully before continuing.
    private void ensureUserIsLoggedOut()
    {
        try
        {
            // Get the user if one is logged in.
            Subject currentUser = getSubject();
            if (currentUser == null)
                return;

            // Log the user out and kill their session if possible.
            currentUser.logout();
            Session session = currentUser.getSession(false);
            if (session == null)
                return;

            session.stop();
        }
        catch (Exception e)
        {
            // Ignore all errors, as we're trying to silently 
            // log the user out.
        }
    }

    private void logoutUser() {
        Subject currentUser = SecurityUtils.getSubject();
        System.out.println("Logging out: " + currentUser.getPrincipal().toString());
//        if (currentUser.isAuthenticated())
            currentUser.logout();
    }

}
