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

import io.netty.handler.codec.http.FullHttpRequest;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http.HttpResponseStatus.SEE_OTHER;
import static io.netty.handler.codec.http.HttpResponseStatus.UNAUTHORIZED;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.slf4j.LoggerFactory;
import uk.ac.embl.ebi.ega.accessservice.EgaSecureAccessService;
import uk.ac.embl.ebi.ega.accessservice.utils.SigVer;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;

public class UserService extends ServiceTemplate implements Service {
    
    private static final transient org.slf4j.Logger log = LoggerFactory.getLogger(UserService.class);

    @Override
    public JSONObject handle(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, SigVer sig, EgaSecureAccessService ref) {
        JSONObject json = new JSONObject(); // Start out with common JSON Object

        // /login
        // /resume
        // /logout        

        try {
            String function = id.get(0);
            String[] result = null; // Holds JDBC Database Query results
            String user = "", pass = "";
            boolean login = true;
            
            Map<String,String> body = new HashMap<>();
            if (function.equals("login")) { // ---------------------------------/login
                if (request.headers().contains("Authorization")) {
                    String auth = request.headers().get("Authorization").toString();
                    if (auth != null) {
                        byte[] decoded = Base64.getDecoder().decode(auth.substring(6));
                        String auth_full = new String(decoded, "UTF-8") + "\n";
                        user = auth_full.substring(0, auth_full.indexOf(":")).trim();
                        pass = auth_full.substring(auth_full.indexOf(":")+1, auth_full.length()).trim();
                        System.out.println("Basic: " + user + "  " + pass);
                    }
                } else {
                    body.put("username", "");
                    body.put("password", "");
                    int elements = decodeRequestBody(request, "loginrequest", body);
                    user = body.get("username");
                    pass = body.get("password");
                }
            } else if (function.equals("resume")) { // -------------------------/resume
                String user_ = parameters.get("user");
                user = URLDecoder.decode(user_, "UTF-8");
                login = false;
                Subject currentUser = SecurityUtils.getSubject();
        
                if (user!=null && !user.equalsIgnoreCase("null") && currentUser != null) {
                    if (currentUser!=null && currentUser.isAuthenticated() && currentUser.getSession() != null) {
                        try {
                            currentUser.getSession().touch();
                            PrincipalCollection principals = currentUser.getPrincipals();
                            String u = principals.toString();

                            if (u!=null && !u.equalsIgnoreCase("null") && u.equalsIgnoreCase(user)) {
                                json.put("header", responseHeader(OK)); // Header Section of the response
                                result = new String[]{"success", currentUser.getSession().getId().toString()};
                            } else {
                                json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                                result = new String[]{"false"};
                            }
                        } catch (UnknownSessionException ex) {
                            json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                            result = new String[]{"false", ex.toString()};
                        } catch (Throwable t) {
                            System.out.println("Error:: " + t.toString());
                        }
                    } else {
                        json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                        result = new String[]{"false"};
                    }                    
                } else {
                    json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                    result = new String[]{"false"};
                }
                
            } else if (function.equals("logout")) { // -------------------------/logout -- cluster-aware
                String sId = null;
                Subject currentUser = null;
                if (parameters.containsKey("session")) {
                    sId = parameters.get("session");
                    currentUser = new Subject.Builder().sessionId(sId).buildSubject();
                } else {
                    currentUser = SecurityUtils.getSubject();
                }
                logoutUser(currentUser);
                login = false;
                result = new String[]{"logged out"};
                json.put("header", responseHeader(OK));
            } else { // id is interpreted as username --------------------------
                pass = parameters.get("pass");
                user = URLDecoder.decode(function, "UTF-8");
            }

            boolean Globus = false;
            if (id.size()>1) {
                String id_ = id.get(1);
                if (id_.equalsIgnoreCase("globus")) {
                    Globus = true;
                    login = false;
                }
            }
            
            if (login) { // authenticate provided username, password
                result = authenticateUser(user, pass);
                if (result[0].equalsIgnoreCase("null")) result[0] = "false";
                
                if (result!=null && result.length>0 && result[0].toLowerCase().startsWith("success")) {
                    json.put("header", responseHeader(OK)); // Header Section of the response
                    
                    result = new String[]{"success", result[1]}; // pass session ID back to user
                } else {
                    json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                    result = new String[]{"false"};
                }
            } else if (Globus) {
                result = new String[]{authenticateGlobus(user, pass)};
                if (result[0].equalsIgnoreCase("null")) result[0] = "false";
                
                if (result!=null && result.length>0 && result[0].toLowerCase().startsWith("success")) {
                    json.put("header", responseHeader(OK)); // Header Section of the response
                } else {
                    json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                }
            }
            
            json.put("response", responseSection(result)); // Either 'OK' or Token String
        } catch (JSONException | UnsupportedEncodingException | UnknownSessionException ex) {
            try {
                json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
                //json.put("response", responseSection(null));            
            } catch (JSONException ex1) {
                Logger.getLogger(StatService.class.getName()).log(Level.SEVERE, null, ex1);
            }
            Logger.getLogger(UserService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Throwable ex) {
            Logger.getLogger(UserService.class.getName()).log(Level.SEVERE, null, ex);
            EgaSecureAccessService.log("/user Exeption ("+""+"): " + ex.getMessage());
        }

        return json;
    }

    // Authenticate user (email) against database by comparing Hash values
    private String[] authenticateUser(String user, String pass) {
        ensureUserIsLoggedOut();
        Subject currentUser = SecurityUtils.getSubject();

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
        String[] text = {"", ""};
        if (currentUser!=null && !currentUser.isAuthenticated()) {
            UsernamePasswordToken token = new UsernamePasswordToken(user, pass);
            token.setRememberMe(false);
            try {
                currentUser.login(token);
                text[0] = "Success: " + token.getPrincipal();
                text[1] = currentUser.getSession().getId().toString();
                log.info(text[0]);
            } catch (UnknownAccountException uae) {
                text[0] = "There is no user with username of " + token.getPrincipal();
                log.info(text[0]);
            } catch (IncorrectCredentialsException ice) {
                text[0] = "Password for account " + token.getPrincipal() + " was incorrect!";
                log.info(text[0]);
            } catch (LockedAccountException lae) {
                text[0] = "The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.";
                log.info(text[0]);
            }
            // ... catch more exceptions here (maybe custom ones specific to your application?
            catch (AuthenticationException ae) {
                //unexpected condition?  error?
                System.out.println(" ->> ");
                System.out.println(text[0]);
                System.out.println(ae.getLocalizedMessage());
            }
            catch (Throwable th) {
            System.out.println(" --> " + th.getLocalizedMessage());
            }
        }
        
        //try {
        //    Session session = currentUser.getSession();
        //    System.out.println(session.getHost());
        //    System.out.println(session.getId());
        //    System.out.println(session.getLastAccessTime().toLocaleString());
        //    if (currentUser.getPrincipal()!=null) System.out.println(currentUser.getPrincipal().toString());
        //} catch (Throwable th) {}
        
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

    private void logoutUser(Subject currentUser) {
        try {
            if (currentUser!=null) {
                if (currentUser.getPrincipal()!=null)
                    System.out.println("Logging out: " + currentUser.getPrincipal().toString());
                currentUser.logout();
            }
        } catch (Throwable th) {;}
    }
    
    // *************************************************************************
    
    private String authenticateGlobus(String user, String pass) {
        String token = null;
        
        
        
        return token;
    }
    
}
