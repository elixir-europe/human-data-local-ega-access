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
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Map;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import uk.ac.embl.ebi.ega.accessservice.EgaSecureAccessService;
import uk.ac.embl.ebi.ega.accessservice.utils.EgaFile;
import uk.ac.embl.ebi.ega.accessservice.utils.SigVer;
import us.monoid.json.JSONArray;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;
import us.monoid.web.JSONResource;
import us.monoid.web.Resty;

/**
 *
 * @author asenf
 */
public class DatasetService extends ServiceTemplate implements Service {

    @Override
    public JSONObject handle(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, SigVer sig, EgaSecureAccessService ref) {
        JSONObject json = new JSONObject(); // Start out with common JSON Object

        String function = (id!=null&&id.size()>1)?id.get(1):"";

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
        } else {
            currentUser = SecurityUtils.getSubject();
        }
        
        if (currentUser==null) {System.out.println("User Null");return null;}
        if (currentUser.getPrincipals()==null) {System.out.println("Principal Null");return null;}

        // /datasets
        // /datasets/{dataset}/files
        // /datasets/{dataset}/files/{file}

        if (currentUser != null) {
            if (id==null || function.length()==0) { // dataset not specified: list datasets
                getUserDatasets(json, currentUser);
            } else if (function.equalsIgnoreCase("files")) {
                boolean permission = false;
                String dataset = id.get(0);
                if (currentUser.hasRole(dataset)) {
                    String fID = (id.size()>2)?id.get(2):"";
                    getDatasetUserFiles(dataset, fID, json, currentUser);
                } else {
                    try {
                        json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                    } catch (Throwable t) {}
                }
            }
        } else {
            try {
                json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                json.put("response", responseSection(new String[]{"Unable to get CurrentUser Error in Dataset"}));
            } catch (Throwable t) {}
        }

        return json;
    }
    
    // Get Dataset IDs for a User (get Shiro Roles)
    private void getUserDatasets(JSONObject json, Subject currentUser) {
        String[] result = null;
        
        // If the user is authenticated, show all permisions (i.e. datasets)
        try {
            if (currentUser!=null && currentUser.isAuthenticated()) {
                currentUser.getSession().touch();
                PrincipalCollection principals = currentUser.getPrincipals();

                String url = EgaSecureAccessService.getServer("data");

                // This lists all datasets to which the user has been granted access
                url+= "/users/" + principals.toString() + "/datasets";

                Resty r = new Resty();
                JSONResource json_ = null;
                try {
                    json_ = r.json(url);

                    JSONObject jobj = (JSONObject) json_.get("response");
                    JSONArray jsonarr = (JSONArray)jobj.get("result");

                    result = new String[jsonarr.length()];
                    for (int i=0; i<jsonarr.length(); i++)
                            result[i] = jsonarr.getString(i);

                    json.put("header", responseHeader(OK)); // Header Section of the response
                    json.put("response", responseSection(result));            
                } catch (Exception ex) {
                    try {
                        json.put("header", responseHeader(SEE_OTHER)); // Header Section of the response
                        json.put("response", responseSection(new String[]{ex.getMessage(), "Error Reading Datasets from DATA Service."}));
                    } catch (JSONException  t) {}
                }
            }
        } catch (ExpiredSessionException | UnknownSessionException ex) {
            System.out.println("Error: " + ex.getMessage());
            try {
                json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                json.put("response", responseSection(new String[]{ex.getMessage(), "Expired or Unknown Session Error in Dataset"}));
            } catch (Throwable t) {}
        }
   }    

    // List datasets, with built-in permissions check
    private void getDatasetUserFiles(String dataset, String fID, JSONObject json, Subject currentUser) {
        // If the user is authenticated, and permitted so see the dataset
        try {
            if (currentUser!=null && currentUser.isAuthenticated() && currentUser.hasRole(dataset)) {
                currentUser.getSession().touch();            
                PrincipalCollection principals = currentUser.getPrincipals();

                String url = EgaSecureAccessService.getServer("data");

                // This lists all files in a dataset, if the user has access
                url+= "/users/" + principals.toString() + "/datasets/" + dataset + "/files";

                Resty r = new Resty();
                JSONResource json_ = null;
                try {
                    System.out.println("URL: " + url);
                    json_ = r.json(url);

                    JSONObject jobj = (JSONObject) json_.get("response");
                    JSONArray jsonarr = (JSONArray)jobj.get("result");

                    //result = new String[jsonarr.length()];
                    EgaFile[] result = new EgaFile[jsonarr.length()];
                    for (int i=0; i<jsonarr.length(); i++) {
                        // Retrieve File info in Object
                        JSONObject oneFile = (JSONObject) jsonarr.get(i);
                        String fileid = oneFile.getString("fileID");
                        String filename = oneFile.getString("fileName");
                        String indexname = oneFile.getString("fileIndex");
                        String dataset_ = oneFile.getString("fileDataset");
                        //long size = oneFile.getLong("size");
                        long size = Long.parseLong(oneFile.getString("fileSize"));
                        String md5 = oneFile.getString("fileMD5");
                        String filestatus = oneFile.getString("fileStatus");

                        result[i] = new EgaFile(fileid, filename, indexname, dataset_, size, md5, filestatus);
                    }

                    json.put("header", responseHeader(OK)); // Header Section of the response
                    json.put("response", responseSection(result));            

                } catch (Exception ex) {
                    try {
                        json.put("header", responseHeader(SEE_OTHER)); // Header Section of the response
                        json.put("response", responseSection(new String[]{ex.getMessage(), "Error Reading Datasets Files from DATA Service."}));
                    } catch (JSONException t) {}
                }

            }
        } catch (ExpiredSessionException | UnknownSessionException ex) {
            try {
                json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                json.put("response", responseSection(new String[]{ex.getMessage(), "Expired or Unknown Session Error in DatasetFiles"}));
            } catch (Throwable t) {}
        }
    }

    private JSONObject responseSection(EgaFile[] files) throws JSONException {
        JSONObject response = new JSONObject();

        response.put("numTotalResults", files.length);
        response.put("resultType", "us.monoid.json.JSONArray");
        
        JSONArray arr = new JSONArray();
        for (int i=0; i<files.length; i++)
            arr.put(files[i].getMap());
        
        JSONArray mJSONArray = files!=null?arr:new JSONArray();
        response.put("result", mJSONArray);
        
        return response;        
    }
}
