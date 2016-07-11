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
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http.HttpResponseStatus.UNAUTHORIZED;
import static io.netty.handler.codec.http.HttpResponseStatus.SEE_OTHER;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.slf4j.LoggerFactory;
import uk.ac.embl.ebi.ega.accessservice.EgaSecureAccessService;
import uk.ac.embl.ebi.ega.accessservice.utils.EgaFile;
import uk.ac.embl.ebi.ega.accessservice.utils.EgaPermission;
import uk.ac.embl.ebi.ega.accessservice.utils.EgaTicket;
import uk.ac.embl.ebi.ega.accessservice.utils.RestyTimeOutOption;
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

public class AppService extends ServiceTemplate implements Service {
    
    private static final transient org.slf4j.Logger log = LoggerFactory.getLogger(AppService.class);

    @Override
    public JSONObject handle(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, SigVer sig_, EgaSecureAccessService ref) {
        JSONObject json = new JSONObject(); // Start out with common JSON Object
    
        // IP Whitelist has already been checked at this point
    
        
        // /requests/new        
        // /requests/{user}/{requestlabel}
        // /requests/{user}/{requestlabel}/{ticket}

        // /tickets/{ticket}?key={}
        // /tickets/{ticket}?key={} [DELETE]

        // /users/{user_email}/datasets?dac={dac}      -- All Datasets for a User, by DAC

        // /datasets/{dataset_id}/users/               -- All Users for a Dataset
        // /datasets/{dataset_id}/users/{user_email}   -- Yes/No

        // /files/{file_id}?key={}
        
        // ALL URLs will have "?time={time}" parameter! Used to limit validity of a request signature
        
        try {
            HttpResponseStatus status = null;
            
            // Digitally signed String, supplied by Client
            HttpHeaders headers = request.headers();
            String signature = "";
            try {
                signature = headers.get("X-Client-Sig").toString();
            } catch (Throwable t) {signature = null;}            

            // Process each function separately 
            String function = id.get(0);
            if (function.equalsIgnoreCase("requests")) {
                handleRequests(id, parameters, request, sig_, ref, signature, json);
                
            } else if (function.equalsIgnoreCase("tickets")) {
                handleTickets(id, parameters, request, sig_, ref, signature, json);
                
            } else if (function.equalsIgnoreCase("users")) {
                handleUsers(id, parameters, request, sig_, ref, signature, json);
                
            } else if (function.equalsIgnoreCase("datasets")) {
                handleDatasets(id, parameters, request, sig_, ref, signature, json);
                
            } else if (function.equalsIgnoreCase("files")) {
                handleFiles(id, parameters, request, sig_, ref, signature, json);
                
            } else {
                status = NOT_FOUND; // URL incorrect
                json.put("header", responseHeader(status)); // Header Section of the response
                return json;
            }
            
        } catch (JSONException | UnsupportedEncodingException ex) {
            try {
                json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
            } catch (JSONException ex1) {
                Logger.getLogger(StatService.class.getName()).log(Level.SEVERE, null, ex1);
            }
            Logger.getLogger(AppService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AppService.class.getName()).log(Level.SEVERE, null, ex);
        }

        return json;
    }
    
    // -------------------------------------------------------------------------
    // Signature verifiction - given signature, re-build signed String, IP used
    private boolean verifySign(SigVer sig_, String sig, String signature, String clientip, String key, String time) {
        boolean verified = false;
        
        if (signature!=null)
            verified = sig_.SigAccessVerification(sig, signature, clientip, time);
        else {
            String k = sig_.getKey(clientip); // uses default setting
            if (key.equals(k))
                verified = true;
        }
        
        return verified;
    }
        
    // Function Handlers -------------------------------------------------------
        // /requests/new                            POST new requests
        // /requests/{user}/{requestlabel}          List Request Tickets
        // /requests/{user}/{requestlabel}/{ticket} List one Request Ticket
    private void handleRequests(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, SigVer sig_, EgaSecureAccessService ref, String signature, JSONObject json) throws IOException, JSONException {
            String sub_function = id.size()>1?id.get(1):"";            
            String time = parameters.get("time");
            
            // New Request, or List Existing Request
            if (sub_function.equalsIgnoreCase("new")) {
                
                Map<String,String> body = new HashMap<>();
                body.put("username", "");
                body.put("userip", "");
                body.put("dataset", "");
                body.put("fileid", "");
                body.put("label", "");
                body.put("rekey", "");

                String username = "", userip = "", dataset = "", fileid = "", label = "", rekey = ""; 
                int elements = decodeRequestBody(request, "apprequest", body);            
                username = body.get("username");
                userip = body.get("userip");
                dataset = body.get("dataset");
                fileid = body.get("fileid");
                label = body.get("label");
                rekey = body.get("rekey");

                // Build request-specific signature
                String sig = "";
                sig += "username" + username + "userip" + userip + "dataset" + dataset + "fileid" + fileid + "label" + label + "rekey" + rekey + "time" + time;
                
                // Verify Signature, or validate client key
                boolean verified = false;
                verified = verifySign(sig_, sig, signature, parameters.get("ip"), parameters.get("key"), time);
                
                // If Signature correct, POST new request
                if (verified)
                    appRequest(username, userip, dataset, fileid, label, rekey, json);
                else
                    json.put("header", responseHeader(UNAUTHORIZED));
            } else {
                String user = sub_function;
                String label = id.size()>2?id.get(2):"";
                String ticket = id.size()>3?id.get(3):"";
                
                String sig = "";
                sig += "username" + user + "request" + label + "time" + time;

                // Verify Signature, or validate client key
                boolean verified = verifySign(sig_, sig, signature, parameters.get("ip"), parameters.get("key"), time);
                
                // If Signature correct, POST new request
                if (verified)
                    accessRequest(json, user, label, ticket);
                else
                    json.put("header", responseHeader(UNAUTHORIZED));
            }
    }
    
        // /tickets/{ticket}?key={}
        // /tickets/{ticket}?key={} [DELETE]
    private void handleTickets(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, SigVer sig_, EgaSecureAccessService ref, String signature, JSONObject json) throws JSONException {
            String ticket = id.size()>1?id.get(1):"";
            String time = parameters.get("time");

            String sig = "";
            sig += "ticket" + ticket + "time" + time;

            // Verify Signature, or validate client key
            boolean verified = verifySign(sig_, sig, signature, parameters.get("ip"), parameters.get("key"), time);
            verified = true;

            // If Signature correct, POST new request
            if (verified)
                accessTicket(json, ticket, request.method());            
            else
                json.put("header", responseHeader(UNAUTHORIZED));            
    }
    

        // /users/{user_email}/datasets?dac={dac}      -- All Datasets for a User, by DAC
    private void handleUsers(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, SigVer sig_, EgaSecureAccessService ref, String signature, JSONObject json) throws JSONException {
            String user = id.size()>1?id.get(1):"";
            String sub_function = id.size()>2?id.get(2):"";
            String time = parameters.get("time");
            String dac = parameters.get("dac");
            
            String sig = "";
            sig += "user" + user + "dac" + dac + "time" + time;

            // Verify Signature, or validate client key
            boolean verified = verifySign(sig_, sig, signature, parameters.get("ip"), parameters.get("key"), time);

            // If Signature correct get information
            if (verified)
                getDatasetsByUserAndDAC(json, user, dac);
            else
                json.put("header", responseHeader(UNAUTHORIZED));            
    }
    

        // /datasets/{dataset_id}/users/               -- All Users for a Dataset
        // /datasets/{dataset_id}/users/{user_email}   -- Yes/No <-- expanded {date, etc.}
    private void handleDatasets(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, SigVer sig_, EgaSecureAccessService ref, String signature, JSONObject json) throws JSONException {
            String dataset = id.size()>1?id.get(1):"";
            String sub_function = id.size()>2?id.get(2):"";
            String user = id.size()>3?id.get(3):"";
            String time = parameters.get("time");
        
            String sig = "";
            sig += "dataset" + dataset + "time" + time;

            // Verify Signature, or validate client key
            //boolean verified = verifySign(sig_, sig, signature, parameters.get("ip"), parameters.get("key"), time);
            boolean verified = true;

            // If Signature correct, POST new request
            if (verified) {
                if (user!=null && user.length() > 0) { // /datasets/{dataset_id}/users/{user_email}
                    getUserPermissionByDataset(json, user, dataset);
                } else { // /datasets/{dataset_id}/users/
                    getUsersByDataset(json, dataset);
                }
            } else
                json.put("header", responseHeader(UNAUTHORIZED));            
    }
    
    
    // /files/{file_id} -- information about one file
    private void handleFiles(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, SigVer sig_, EgaSecureAccessService ref, String signature, JSONObject json) throws JSONException {
            String fileid = id.size()>1?id.get(1):"";
            String time = parameters.get("time");
        
            String sig = "";
            sig += "files" + fileid + "time" + time;

            // Verify Signature, or validate client key
            //boolean verified = verifySign(sig_, sig, signature, parameters.get("ip"), parameters.get("key"), time);
            boolean verified = true;

            // If Signature correct, POST new request
            if (verified) {
                getFilesByID(json, fileid);
            } else
                json.put("header", responseHeader(UNAUTHORIZED));            
    }
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    
    // Used to POST download requests directly **************************
    private void appRequest(String user, String userip, String dataset, String fileid, String label, String rekey, JSONObject json) {

        // Get individual files from CSV string
        ArrayList<String> reqFiles = new ArrayList<>();
        StringTokenizer token = new StringTokenizer(fileid, ",");
        while (token.hasMoreTokens())
            reqFiles.add(token.nextToken());
        
        String url = EgaSecureAccessService.getServer("data");
        
        try {
            // Step 1 - Get Files for Dataset for User (AuZN verification)
            String url_ = url + "/users/" + user + "/datasets/" + dataset + "/files";

            Resty r = new Resty();
            JSONResource json_ = null;
            json_ = r.json(url_);

            JSONObject jobj = (JSONObject) json_.get("response");
            JSONArray jsonarr = (JSONArray)jobj.get("result");
        
            // Step 2 - Match files from requets; remove files not in the permitted dataset
            for (int i=0; i<jsonarr.length(); i++) {
                if (!reqFiles.contains(jsonarr.getString(i)))
                    reqFiles.remove(jsonarr.getString(i));
            }

            // Step 3 - Write request to database
            ArrayList<String> res = new ArrayList<>();
            String[] result = null;
            for (int i=0; i<reqFiles.size(); i++) {
                String url__ = url + "/users/" + user + "/requests/download/file/" + reqFiles.get(i);
                
                JSONObject json_request = new JSONObject();
                try {
                    json_request.put("id", reqFiles.get(i));
                    json_request.put("rekey", rekey);
                    json_request.put("downloadType", "STREAM");
                    json_request.put("descriptor", label);
                } catch (JSONException ex) {
                    System.out.println("--- " + ex.getLocalizedMessage());
                }
                
                try {
                    json_ = r.json(url__, form( data("downloadrequest", content(json_request))) );

                    JSONObject jobj_ = (JSONObject) json_.get("response");
                    JSONArray jsonarr_ = (JSONArray)jobj_.get("result");

                    result = new String[jsonarr.length()];
                    for (int i_=0; i_<jsonarr_.length(); i_++)
                        result[i_] = jsonarr.getString(i_);

                    json.put("header", responseHeader(OK)); // Header Section of the response
                    json.put("response", responseSection(result));            

                } catch (Exception ex) {
                    try {
                        json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
                    } catch (JSONException ex1) {}
                    Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
                }

            }

            // Step 4 - Return result
            json.put("header", responseHeader(OK)); // Header Section of the response
            json.put("response", responseSection(result));            
        
        } catch (Exception ex) {
            try {
                json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
            } catch (JSONException ex1) {}
            Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    // Used by Globus Process to get request information for a specific user ***
    private void accessRequest(JSONObject json, String user, String requestlabel, String ticket) {
        
        String url = EgaSecureAccessService.getServer("data");
        
        // Get requested information from Data service
        String url__ = url + "/users/" + user + "/requests";
        if (ticket==null || ticket.length()==0) {
            url__ += "/request/" + requestlabel + "/tickets";
        } else {
            url__ += "/ticket/" + ticket;
        }
        
        EgaTicket[] result = null;
        try {        
            Resty r = new Resty();
            JSONResource json_ = null;
            json_ = r.json(url__);

            JSONObject jobj = (JSONObject) json_.get("response");
            JSONArray jsonarr = (JSONArray)jobj.get("result");

            result = new EgaTicket[jsonarr.length()];
            for (int i=0; i<jsonarr.length(); i++) {
                JSONObject oneTicket = (JSONObject) jsonarr.get(i);

                String ticket_ = oneTicket.getString("ticket");
                String label = oneTicket.getString("label");
                String fileID = oneTicket.getString("fileID");
                String fileType = oneTicket.getString("fileType");
                String fileSize = oneTicket.getString("fileSize");
                String fileName = oneTicket.getString("fileName");
                String user_ = oneTicket.getString("user");
                //String encryptionKey = oneTicket.getString("encryptionKey");
                //String transferType = oneTicket.getString("transferType");
                //String transferTarget = oneTicket.getString("transferTarget");
                String encryptionKey = "";
                String transferType = "";
                String transferTarget = "";

                result[i] = new EgaTicket(ticket_, label, fileID, fileType, fileSize, fileName, encryptionKey, transferType, transferTarget, user_);
            }
            List<Map<String,String>> maps = new ArrayList<>();
            for (EgaTicket oneTicket1 : result) {
                maps.add(oneTicket1.getMap());
            }

            json.put("header", responseHeader(OK)); // Header Section of the response
            json.put("response", responseSection(maps));            

        } catch (Exception ex) {
            try {
                json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
            } catch (JSONException ex1) {}
            Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }

    private void accessTicket(JSONObject json, String ticket, HttpMethod method) {
        
        String url = EgaSecureAccessService.getServer("data");
        
        // Get requested information from Data service
        String url__ = url + "/tickets/" + ticket;
        
        EgaTicket[] result = null;
        try {        
            Resty r = new Resty(new RestyTimeOutOption(8000,8000));
            JSONResource json_ = null;
   
            int code = 0, countdown = 3;
            do {
                json_ = r.json(url__);
                JSONObject jheader = (JSONObject) json_.get("header");
                code = jheader.getInt("code");
            } while (code != 200 && countdown-- > 0);
            
            if (code!=200)
                EgaSecureAccessService.log("Ticket Error - " + url__ + "    " + code);
            
            JSONObject jobj = (JSONObject) json_.get("response");
            JSONArray jsonarr = (JSONArray)jobj.get("result");

            result = new EgaTicket[jsonarr.length()];
            String user = "";
            for (int i=0; i<jsonarr.length(); i++) {
                JSONObject oneTicket = (JSONObject) jsonarr.get(i);

                String ticket_ = oneTicket.getString("ticket");
                String label = oneTicket.getString("label");
                String fileID = oneTicket.getString("fileID");
                String fileType = oneTicket.getString("fileType");
                String fileSize = oneTicket.getString("fileSize");
                String fileName = oneTicket.getString("fileName");
                String encryptionKey = oneTicket.getString("encryptionKey");
                String transferType = oneTicket.getString("transferType");
                String transferTarget = oneTicket.getString("transferTarget");
                user = oneTicket.getString("user");

                result[i] = new EgaTicket(ticket_, label, fileID, fileType, fileSize, fileName, encryptionKey, transferType, transferTarget, user);
            }
            List<Map<String,String>> maps = new ArrayList<>();
            for (EgaTicket oneTicket1 : result) {
                maps.add(oneTicket1.getMap());
            }
            
            if (method == HttpMethod.DELETE) {
                System.out.println("DELETE Ticket");
                
                String url__delete = url + "/userdeletes/" + user + "/requests/delete/ticket/" + ticket;
                JSONResource json_delete = r.json(url__delete, delete());
                JSONObject jobj_delete = (JSONObject) json_delete.get("response");
                JSONArray jsonarr_delete = (JSONArray)jobj_delete.get("result");
                
                // * /userdeletes/{email}/requests/delete/ticket/{ticket} [DELETE]    (Test 13)
                json.put("header", responseHeader(OK)); // Header Section of the response
                String[] response = new String[jsonarr_delete.length()];
                for (int i=0; i<jsonarr_delete.length(); i++)
                    response[i] = jsonarr_delete.getString(i);
                json.put("response", response);
                
            } else {
                json.put("header", responseHeader(OK)); // Header Section of the response
                json.put("response", responseSection(maps));
            }

        } catch (Exception ex) {
            try {
                json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
            } catch (JSONException ex1) {}
            Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    private void getDatasetsByUserAndDAC(JSONObject json, String user, String dac) {
        String url = EgaSecureAccessService.getServer("data");
        
        // Get requested information from Data service
        String url__ = url + "/users/" + user + "/datasets/dac/" + dac;
        
        String[] result = null;
        try {        
            Resty r = new Resty(new RestyTimeOutOption(8000,8000));
            JSONResource json_ = null;
   
            int code = 0, countdown = 3;
            do {
                json_ = r.json(url__);
                JSONObject jheader = (JSONObject) json_.get("header");
                code = jheader.getInt("code");
            } while (code != 200 && countdown-- > 0);
            
            if (code!=200)
                EgaSecureAccessService.log("Ticket Error - " + url__ + "    " + code);
            
            JSONObject jobj = (JSONObject) json_.get("response");
            JSONArray jsonarr = (JSONArray)jobj.get("result");

            result = new String[jsonarr.length()];
            for (int i=0; i<jsonarr.length(); i++)
                result[i] = jsonarr.getString(i);
            
            json.put("header", responseHeader(OK)); // Header Section of the response
            json.put("response", responseSection(result));

        } catch (Exception ex) {
            try {
                json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
            } catch (JSONException ex1) {}
            Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void getUsersByDataset(JSONObject json, String dataset) {
        String url = EgaSecureAccessService.getServer("data");
        
        // Get requested information from Data service
        String url__ = url + "/datasets/" + dataset + "/users";
        
        String[] result = null;
        try {        
            Resty r = new Resty(new RestyTimeOutOption(8000,8000));
            JSONResource json_ = null;
   
            int code = 0, countdown = 3;
            do {
                json_ = r.json(url__);
                JSONObject jheader = (JSONObject) json_.get("header");
                code = jheader.getInt("code");
            } while (code != 200 && countdown-- > 0);
            
            if (code!=200)
                EgaSecureAccessService.log("Ticket Error - " + url__ + "    " + code);
            
            JSONObject jobj = (JSONObject) json_.get("response");
            JSONArray jsonarr = (JSONArray)jobj.get("result");

            result = new String[jsonarr.length()];
            for (int i=0; i<jsonarr.length(); i++)
                result[i] = jsonarr.getString(i);
            
            json.put("header", responseHeader(OK)); // Header Section of the response
            json.put("response", responseSection(result));

        } catch (Exception ex) {
            try {
                json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
            } catch (JSONException ex1) {}
            Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void getUserPermissionByDataset(JSONObject json, String user, String dataset) {
        String url = EgaSecureAccessService.getServer("data");
        
        // Get requested information from Data service
        String url__ = url + "/datasets/" + dataset + "/users/" + user;
        
        EgaPermission result = null;
        try {        
            Resty r = new Resty(new RestyTimeOutOption(8000,8000));
            JSONResource json_ = null;
   
            int code = 0, countdown = 3;
            do {
                json_ = r.json(url__);
                JSONObject jheader = (JSONObject) json_.get("header");
                code = jheader.getInt("code");
            } while (code != 200 && countdown-- > 0);
            
            if (code!=200)
                EgaSecureAccessService.log("App Permission Error - " + url__ + "    " + code);
            
            JSONObject jobj = (JSONObject) json_.get("response");
            JSONArray jobjarr = (JSONArray) jobj.get("result");
            JSONObject jobjres = (JSONObject)jobjarr.get(0);

            result = new EgaPermission(jobjres.getString("permitted"), jobjres.getString("permission_date"), jobjres.getString("changed_by"));
            
            json.put("header", responseHeader(OK)); // Header Section of the response
            json.put("response", responseSection(result.getMap()));

        } catch (Exception ex) {
            try {
                json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
            } catch (JSONException ex1) {}
            Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void getFilesByID(JSONObject json, String fileid) {
        String url = EgaSecureAccessService.getServer("data");
        
        // Get requested information from Data service
        String url__ = url + "/files/" + fileid;
        
        EgaFile result = null;
        try {        
            Resty r = new Resty(new RestyTimeOutOption(8000,8000));
            JSONResource json_ = null;
   
            int code = 0, countdown = 3;
            do {
                json_ = r.json(url__);
                JSONObject jheader = (JSONObject) json_.get("header");
                code = jheader.getInt("code");
            } while (code != 200 && countdown-- > 0);
            
            if (code!=200)
                EgaSecureAccessService.log("App Permission Error - " + url__ + "    " + code);
            
            JSONObject jobj = (JSONObject) json_.get("response");
            JSONArray jobjarr = (JSONArray) jobj.get("result");
            JSONObject jobjres = (JSONObject)jobjarr.get(0);

            result = new EgaFile(jobjres.getString("fileID"), jobjres.getString("fileName"), jobjres.getString("fileIndex"),
                                 jobjres.getString("fileDataset"), Integer.parseInt(jobjres.getString("fileSize")), jobjres.getString("fileMD5"),
                                 jobjres.getString("fileStatus"));
            
            json.put("header", responseHeader(OK)); // Header Section of the response
            json.put("response", responseSection(result.getMap()));

        } catch (Exception ex) {
            try {
                json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
            } catch (JSONException ex1) {}
            Logger.getLogger(DatasetService.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
