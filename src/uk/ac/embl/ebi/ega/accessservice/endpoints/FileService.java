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
import io.netty.handler.codec.http.HttpResponseStatus;
import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;
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
import uk.ac.embl.ebi.ega.accessservice.utils.RestyTimeOutOption;
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
public class FileService extends ServiceTemplate implements Service {

    @Override
    public JSONObject handle(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, SigVer sig, EgaSecureAccessService ref) {
        JSONObject json = new JSONObject(); // Start out with common JSON Object

        String fID = (id!=null&&id.size()>0)?id.get(0):"";

         // Enable session clustering - must pass session to 
        String sId = null;
        Subject currentUser = null;
        if (parameters.containsKey("session")) {
            sId = parameters.get("session");
            Serializable ssId = sId;
            int count = 2;
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
                    currentUser.getPreviousPrincipals();
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
       
        if (currentUser==null) return null;

        // /files/{file}
        
        if (fID!=null && fID.length() > 0 && currentUser.isPermitted(fID)) {
            getFile(fID, json, currentUser);
        } else {
            try {
                json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                json.put("response", responseSection(new String[]{"Unable to get CurrentUser Error in File"}));
            } catch (Throwable t) {}
        }

        return json;
    }
    
    // List datasets, with built-in permissions check
    private void getFile(String fID, JSONObject json, Subject currentUser) {

        // If the user is authenticated, and permitted so see the dataset
        try {
            if (currentUser!=null && currentUser.isAuthenticated()) { //  && currentUser.hasRole(dataset)) {
                currentUser.getSession().touch();            
                PrincipalCollection principals = currentUser.getPrincipals();

                String url = EgaSecureAccessService.getServer("data");

                // This lists file details for the specified fID
                url+= "/files/" + fID;

                Resty r = new Resty(new RestyTimeOutOption(8000,8000));
                JSONResource json_ = null;
                int countdown = 3; boolean retry = true;
                while (retry && countdown-- > 0) {
                    try {
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
                            
                            retry = false;
                        }

                        // Check user permission (which is based on the dataset of the file)
                        if (result!=null && result.length>0 && currentUser.hasRole(result[0].getFileDataset())) {
                            json.put("header", responseHeader(OK));
                            json.put("response", responseSection(result));
                        } else if (result!=null && result.length>0 && !currentUser.hasRole(result[0].getFileDataset())) {
                            json.put("header", responseHeader(UNAUTHORIZED));
                            json.put("response", responseSection(new String[]{"User does not have permission to access this File."}));
                        } else if (result!=null && result.length==0) {
                            json.put("header", responseHeader(NOT_FOUND));
                            json.put("response", responseSection(new String[]{"DATA returned no data for specified File.."}));
                        } else {
                            json.put("header", responseHeader(SEE_OTHER));
                            json.put("response", responseSection(new String[]{"General Error Reading Files from DATA Service in File."}));
                        }

                    } catch (Exception ex) {
                        try {
                            json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
                            json.put("response", responseSection(new String[]{ex.getMessage(), "Error Reading Files from DATA Service."}));
                        } catch (JSONException t) {}
                    }
                    
                    if (retry && countdown > 0) {
                        Thread.sleep(500);
                    }
                }

            }
        } catch (ExpiredSessionException | UnknownSessionException ex) {
            try {
                json.put("header", responseHeader(UNAUTHORIZED)); // Header Section of the response
                json.put("response", responseSection(new String[]{ex.getMessage(), "Expired or Unknown Session Error in Files"}));
            } catch (Throwable t) {}
        } catch (InterruptedException ex) {;}
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
