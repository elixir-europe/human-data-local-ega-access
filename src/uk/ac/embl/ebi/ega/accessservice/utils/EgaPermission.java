/*
 * Copyright 2016 EMBL-EBI.
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
package uk.ac.embl.ebi.ega.accessservice.utils;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 *
 * @author asenf
 */
public class EgaPermission {
    private String permitted = null;
    private String permission_date = null;
    private String changed_by = null;
    
    public EgaPermission(String permitted, String permission_date, String changed_by) {
        this.permitted = permitted;
        this.permission_date = permission_date;
        this.changed_by = changed_by;
    }
    
    public void setPermittedt(String permitted) {
        this.permitted = permitted;
    }
    
    public void setPermissionDate(String permission_date) {
        this.permission_date = permission_date;
    }

    public void setChangedBy(String changed_by) {
        this.changed_by = changed_by;
    }
    
    public String getPermitted() {
        return this.permitted;
    }
    
    public String getPermissionDate() {
        return this.permission_date;
    }

    public String getChangedBy() {
        return this.changed_by;
    }
    
    public Map<String,String> getMap() {
        Map<String,String> result = new LinkedHashMap<>();

        result.put("permitted", this.permitted);
        result.put("permission_date", this.permission_date);
        result.put("changed_by", this.changed_by);
                
        return result;
    }
    
}
