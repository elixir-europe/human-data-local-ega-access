/*
 * Copyright 2014 EMBL-EBI.
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
import io.netty.handler.codec.http.HttpResponseStatus;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http.HttpResponseStatus.SEE_OTHER;
import static io.netty.handler.codec.http.HttpResponseStatus.UNAUTHORIZED;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import uk.ac.embl.ebi.ega.accessservice.EgaSecureAccessService;
import uk.ac.embl.ebi.ega.accessservice.utils.EgaTicket;
import uk.ac.embl.ebi.ega.accessservice.utils.SigVer;
import us.monoid.json.JSONArray;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;
import us.monoid.web.JSONResource;
import us.monoid.web.Resty;
import static us.monoid.web.Resty.content;
import static us.monoid.web.Resty.data;
import static us.monoid.web.Resty.delete;
import static us.monoid.web.Resty.form;

/**
 *
 * @author asenf
 */
public class RequestService extends ServiceTemplate implements Service {

    @Override
    public JSONObject handle(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, SigVer sig, EgaSecureAccessService ref) {
        JSONObject json = new JSONObject(); // Start out with common JSON Object

        String function = (id!=null&&id.size()>0)?id.get(0):"";
        String ip = parameters.containsKey("ip")?parameters.get("ip"):"";
        
        // Enable session clustering - must pass session to 
        String sId = null;
        Subject currentUser = null;
        if (parameters.containsKey("session")) {
            sId = parameters.get("session");
            Serializable ssId = sId;
            int count = 3;
            while ((currentUser==null || currentUser.getPrincipals()==null) && count-- > 0) {
                currentUser = new Subject.Builder().sessionId(ssId).buildSubject();
                currentUser.getSession(true).touch();
                
                if (!currentUser.isAuthenticated()) { // Check Session Valid
                    try {
                        HttpResponseStatus custom = new HttpResponseStatus(991, "Session Lost");
                        json.put("header", responseHeader(custom, "Session Lost")); // Header Section of the response
                    } catch (Throwable t) {}
                    return json;                    
                }
                
                if (currentUser==null || currentUser.getPrincipals()==null) {
                    System.out.println("User Null?? " + sId);                    
                    System.out.println("-*---- " + currentUser.getPreviousPrincipals());
                    System.out.println("--*--- " + currentUser.getPrincipal());
                    System.out.println("---*-- " + currentUser.getSession(true));
                    System.out.println("----*- " + currentUser.isAuthenticated());                    
                    try {System.out.println("Sleep");Thread.sleep(1000);} catch (InterruptedException ex) {;}
                }
            }
        } else // Legacy
            currentUser = SecurityUtils.getSubject();

        if (currentUser==null) return null;
        System.out.println("-----* " + currentUser.isAuthenticated());                    

        // /requests
        // /requests/{requestlabel}
        // /requests/{requestlabel}/localize
        // /requests/light
        // /requests/ticket/{ticket}
        // /requests/ticket/delete/{ticket}
        // /requests/delete/{requestlabel}
        // /requests/delete/{requestlabel}/{ticket}
        // /requests/new/datasets/{datasetid}
        // /requests/new/files/{fileid}
        
        if (function.equalsIgnoreCase("new")) { // Create a new Request
            newRequests(id, json, request, currentUser);
        } else if (function.equalsIgnoreCase("delete")) { // Delete a Request or a Ticket
            deleteRequests(id, json, currentUser);
        } else if (function.equalsIgnoreCase("ticket")) { // Delete a Request or a Ticket
            String key = parameters.containsKey("key")?parameters.get("key").toString():null;
            ticketRequests(id, key, json, currentUser);
        } else if (function.equalsIgnoreCase("light")) {
            listRequestsLight(id, ip, json, currentUser);
        } else { // List Request Tickets (all, or by request label)
            listRequestTickets(id, ip, json, currentUser);
        }
            
        return json;
    }

    private void listRequestsLight(ArrayList<String> id, String ip, JSONObject json, Subject currentUser) {
        // If the user is authenticated
        try {
            if (currentUser!=null && currentUser.isAuthenticated()) {
                currentUser.getSession().touch();            
                PrincipalCollection principals = currentUser.getPrincipals();

                String url = EgaSecureAccessService.getServer("data");
                url+= "/users/" + principals.toString() + "/requestslight";

                Resty r = new Resty();
                JSONResource json_ = null;
                try {
                    json_ = r.json(url);

                    JSONObject jobj = (JSONObject) json_.get("response");
                    JSONArray jsonarr = (JSONArray)jobj.get("result");
                    
                    String[] result = new String[jsonarr.length()];
                    for (int i=0; i<jsonarr.length(); i++)
                        result[i] = jsonarr.getString(i);
                
                    json.put("header", responseHeader(OK)); // Header Section of the response
                    json.put("response", responseSection(result));
                } catch (Exception ex) {
                    try {
                        json.put("header", responseHeader(SEE_OTHER, ex.getMessage()));
                    } catch (JSONException ex1) {}
                    Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
                }                
            }
        } catch (ExpiredSessionException | UnknownSessionException ex) {
            try {
                json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                json.put("response", responseSection(new String[]{ex.getMessage()}));
            } catch (Throwable t) {}
        }        
    }
    private void listRequestTickets(ArrayList<String> id, String ip, JSONObject json, Subject currentUser) {
        // If the user is authenticated
        try {
            if (currentUser!=null && currentUser.isAuthenticated()) {
                currentUser.getSession().touch();            
                PrincipalCollection principals = currentUser.getPrincipals();

                String url = EgaSecureAccessService.getServer("data");
                String function = "";

                // This lists all tickets in a request
                if (id.size()==0)
                    url+= "/users/" + principals.toString() + "/requests";
                else if (id.size() > 1) { // Chance Request IP and list all tickets (not strictly a "list")
                    String request = id.get(0);
                    function = id.get(1);
                    if (function.equalsIgnoreCase("localize")) {
                        url+= "/users/" + principals.toString() + "/requests/request/" + request + "/localize?ip=" + ip;
                    } else {
                        url+= "/users/" + principals.toString() + "/requests/request/" + request + "/tickets";
                        function= "";
                    }
                } else if (id.size() > 0) {
                    String request = id.get(0);
                    url+= "/users/" + principals.toString() + "/requests/request/" + request + "/tickets";
                }

                Resty r = new Resty();
                JSONResource json_ = null;
                try {
                    json_ = r.json(url);

                    JSONObject jobj = (JSONObject) json_.get("response");
                    JSONArray jsonarr = (JSONArray)jobj.get("result");

                    //result = new String[jsonarr.length()];
                    if (function.length() == 0) {
                        EgaTicket[] result = new EgaTicket[jsonarr.length()];
                        for (int i=0; i<jsonarr.length(); i++) {
                            JSONObject oneTicket = (JSONObject) jsonarr.get(i);

                            String ticket = oneTicket.getString("ticket");
                            String label = oneTicket.getString("label");
                            String fileID = oneTicket.getString("fileID");
                            String fileType = oneTicket.getString("fileType");
                            String fileSize = oneTicket.getString("fileSize");
                            String fileName = oneTicket.getString("fileName");
                            String user = oneTicket.getString("user");
                                // Limit the amount of information sent to the user /app lists all elements
                            String encryptionKey = ""; //oneTicket.getString("encryptionKey");
                            String transferType = ""; //oneTicket.getString("transferType");
                            String transferTarget = ""; //oneTicket.getString("transferTarget");

                            result[i] = new EgaTicket(ticket, label, fileID, fileType, fileSize, fileName, encryptionKey, transferType, transferTarget, user);
                        }
                        List<Map<String,String>> maps = new ArrayList<>();
                        for (EgaTicket oneTicket1 : result) {
                            maps.add(oneTicket1.getMap());
                        }

                        json.put("header", responseHeader(OK)); // Header Section of the response
                        json.put("response", responseSection(maps));
                    } else {
                        json.put("header", responseHeader(OK)); // Header Section of the response
                        String[] res = (String[]) jsonarr.get(0);
                        json.put("response", responseSection(res));
                    }

                } catch (Exception ex) {
                    try {
                        json.put("header", responseHeader(SEE_OTHER, ex.getMessage()));
                    } catch (JSONException ex1) {}
                    Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        } catch (ExpiredSessionException | UnknownSessionException ex) {
            try {
                json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                json.put("response", responseSection(new String[]{ex.getMessage()}));
            } catch (Throwable t) {}
        }
    }
    
    private void ticketRequests(ArrayList<String> id, String key, JSONObject json, Subject currentUser) {
        // If the user is authenticated
        try {
            if (currentUser!=null && currentUser.isAuthenticated()) {
                currentUser.getSession().touch();            
                PrincipalCollection principals = currentUser.getPrincipals();

                String url = EgaSecureAccessService.getServer("data");

                String function = "";
                String ticket = ""; //id.get(1); // ticket or 'delete'            
                String id_ = id.size()>2?id.get(2):""; // ticket

                // This lists all tickets in a request
                if (id.size()==2) {
                    ticket = id.get(1);
                    url+= "/users/" + principals.toString() + "/requests/ticket/" + ticket;
                } else if (id.size() > 2) { // Chance Request IP and list all tickets (not strictly a "list")
                    function = id.get(1);
                    ticket = id.get(2);

                    // Not Implemented

                }

                Resty r = new Resty();
                JSONResource json_ = null;
                try {
                    json_ = r.json(url);

                    JSONObject jobj = (JSONObject) json_.get("response");
                    JSONArray jsonarr = (JSONArray)jobj.get("result");

                    //result = new String[jsonarr.length()];
                    if (function.length() == 0) {
                        EgaTicket[] result = new EgaTicket[jsonarr.length()];
                        for (int i=0; i<jsonarr.length(); i++) {
                            JSONObject oneTicket = (JSONObject) jsonarr.get(i);

                            String ticket_ = oneTicket.getString("ticket");
                            String label = oneTicket.getString("label");
                            String fileID = oneTicket.getString("fileID");
                            String fileType = oneTicket.getString("fileType");
                            String fileSize = oneTicket.getString("fileSize");
                            String fileName = oneTicket.getString("fileName");
                            String user = oneTicket.getString("user");
                                // Limit the amount of information sent to the user /app lists all elements
                            String encryptionKey = ""; //oneTicket.getString("encryptionKey");
                            String transferType = ""; //oneTicket.getString("transferType");
                            String transferTarget = ""; //oneTicket.getString("transferTarget");

                            result[i] = new EgaTicket(ticket_, label, fileID, fileType, fileSize, fileName, encryptionKey, transferType, transferTarget, user);
                        }
                        List<Map<String,String>> maps = new ArrayList<>();
                        for (EgaTicket oneTicket1 : result) {
                            maps.add(oneTicket1.getMap());
                        }

                        json.put("header", responseHeader(OK)); // Header Section of the response
                        json.put("response", responseSection(maps));
                    } else {
                        json.put("header", responseHeader(OK)); // Header Section of the response
                        String[] res = (String[]) jsonarr.get(0);
                        json.put("response", responseSection(res));
                    }
                } catch (Exception ex) {
                    try {
                        json.put("header", responseHeader(SEE_OTHER, ex.getMessage()));
                    } catch (JSONException ex1) {}
                    Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
                }
            }            
        } catch (ExpiredSessionException | UnknownSessionException ex) {
            try {
                json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                json.put("response", responseSection(new String[]{ex.getMessage()}));
            } catch (Throwable t) {}
        }
    }

    private void newRequests(ArrayList<String> id, JSONObject json, FullHttpRequest request, Subject currentUser) {
        // If the user is authenticated
        try {
            if (currentUser!=null && currentUser.isAuthenticated()) {
                currentUser.getSession().touch();            
                PrincipalCollection principals = currentUser.getPrincipals();

                String url = EgaSecureAccessService.getServer("data");

                String type = id.get(1); // file or dataset
                String id_ = id.get(2); // fileId or datasetId

                // This lists all tickets in a request
                boolean permission = false;
                if (type.equalsIgnoreCase("datasets") && currentUser.hasRole(id_)) {
                    url+= "/users/" + principals.toString() + "/requests/download/dataset/" + id_;
                    permission = true;
                } else if (type.equalsIgnoreCase("files") && currentUser.isPermitted(id_)) {
                    url+= "/users/" + principals.toString() + "/requests/download/file/" + id_;
                    permission = true;
                }
                if (!permission) {
                    try {
                        json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                    } catch (Throwable t) {}
                    return;
                }

                Map<String,String> body = new HashMap<>();
                body.put("rekey", "");
                body.put("downloadType", "");
                body.put("descriptor", "");

                JSONObject json_request = new JSONObject();
                try {
                    int elements = decodeRequestBody(request, "downloadrequest", body);

                    json_request.put("id", id_);
                    json_request.put("rekey", body.get("rekey"));
                    json_request.put("downloadType", body.get("downloadType"));
                    json_request.put("descriptor", body.get("descriptor"));
                } catch (IOException | JSONException ex) {System.out.println("--- " + ex.getLocalizedMessage());}

                Resty r = new Resty();
                JSONResource json_ = null;
                try {
                    json_ = r.json(url, form( data("downloadrequest", content(json_request))) );
System.out.println("Data URL: " + url);

                    JSONObject jobj = (JSONObject) json_.get("response");
                    JSONArray jsonarr = (JSONArray)jobj.get("result");

                    String[] result = new String[jsonarr.length()];
                    for (int i=0; i<jsonarr.length(); i++)
                        result[i] = jsonarr.getString(i);

                    json.put("header", responseHeader(OK)); // Header Section of the response
                    json.put("response", responseSection(result));            

                } catch (Exception ex) {
                    try {
                        json.put("header", responseHeader(SEE_OTHER, ex.getMessage()));
                    } catch (JSONException ex1) {}
                    Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        } catch (ExpiredSessionException | UnknownSessionException ex) {
            try {
                json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                json.put("response", responseSection(new String[]{ex.getMessage()}));
            } catch (Throwable t) {}
        }
    }
    
    private void deleteRequests(ArrayList<String> id, JSONObject json, Subject currentUser) {
        // If the user is authenticated
        try {
            if (currentUser!=null && currentUser.isAuthenticated()) {
                currentUser.getSession().touch();            
                PrincipalCollection principals = currentUser.getPrincipals();

                String url = EgaSecureAccessService.getServer("data");

                String id_ = id.get(1); // file or dataset

                // This lists all tickets in a request
                url+= "/users/" + principals.toString() + "/requests/delete/request/" + id_;
                if (id.size() > 2) {
                    String ticket = id.get(2);
                    url+= "/" + ticket;
                }

                Resty r = new Resty();
                JSONResource json_ = null;
                try {
                    json_ = r.json(url, delete() );

                    JSONObject jobj = (JSONObject) json_.get("response");
                    JSONArray jsonarr = (JSONArray)jobj.get("result");

                    String[] result = new String[jsonarr.length()];
                    for (int i=0; i<jsonarr.length(); i++)
                        result[i] = jsonarr.getString(i);

                    json.put("header", responseHeader(OK)); // Header Section of the response
                    json.put("response", responseSection(result));            

                } catch (Exception ex) {
                    try {
                        json.put("header", responseHeader(SEE_OTHER, ex.getMessage()));
                    } catch (JSONException ex1) {}
                    Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        } catch (ExpiredSessionException | UnknownSessionException ex) {
            try {
                json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                json.put("response", responseSection(new String[]{ex.getMessage()}));
            } catch (Throwable t) {}
        }
        
    }
}
