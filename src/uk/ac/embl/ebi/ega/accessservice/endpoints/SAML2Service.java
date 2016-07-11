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
import java.util.ArrayList;
import java.util.Map;
import uk.ac.embl.ebi.ega.accessservice.EgaSecureAccessService;
import uk.ac.embl.ebi.ega.accessservice.utils.SigVer;
import us.monoid.json.JSONObject;

/**
 *
 * @author asenf
 */
public class SAML2Service extends ServiceTemplate implements Service {

    public void SAM2Service() {
        
    }
    
    @Override
    public JSONObject handle(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, SigVer sig, EgaSecureAccessService ref) {
        JSONObject json = new JSONObject(); // Start out with common JSON Object

        String function = (id!=null&&id.size()>0)?id.get(0):"";

        // /SAML2
        // /SAML2/Unsolicited/SSO       Initiate User Logon, Produce SAML Assertion
        // /SAML2/SSO/POST              Receive Assertion from somewhere else

        // Future: AuZN Queries
        
        // http://saml.xml.org/wiki/idp-initiated-single-sign-on-post-binding
        // https://documentation.pingidentity.com/display/PF610/IdP-Initiated+SSO--POST
        
        
        if (function.equalsIgnoreCase("Unsolicited")) { // IdP-Initiated Logon
            //
        } else if (function.equalsIgnoreCase("SSO")) { // Assertion Consumer Service (?)
            //
        } else { // Nothing specified
            //
        }
        
        return json;
    }
    
}
