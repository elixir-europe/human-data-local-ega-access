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
package uk.ac.embl.ebi.ega.accessservice.utils;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.ini4j.Ini;
import org.ini4j.Profile;
import uk.ac.embl.ebi.ega.accessservice.EgaSecureAccessService;

/**
 *
 * @author asenf
 */
public class SigVer {
    // Ini file location default
    private String iniFile = "sig.ini";
    
    // IP Whitelist && Cert Store
    HashMap<String, Certificate> store;
    HashMap<String, String> sig_store;
    HashMap<String, String> sig_key;
    
    // Place Ini file name in object
    public SigVer(String iniFile) {
        if (iniFile!=null)
            this.iniFile = iniFile;
        
        reLoad();
    }
    
    // Load Ini file again, if there have been any changes (Maybe automate based on file timestamp??)
    public void reLoad() {
        // Read Ini File, get IP Whitelist and Certificates
        Ini ini = null;
        try {
            ini = new Ini(new File(this.iniFile));
System.out.println("--- " + this.iniFile);
        } catch (IOException ex) {
            Logger.getLogger(SigVer.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Read initialization file 
        // First - read a list of orgs; each will then be a headr on the cert file
        if (ini != null) {
            this.store = new HashMap<>(); // Reset Sig Store
            this.sig_store = new HashMap<>();
            this.sig_key = new HashMap<>();
            
            // Populate query strings with it ----------------------------------
            Profile.Section certs = ini.get("certs");

            // Get a list of all expected organizations in the Ini file --------
            String allOrgs = certs.get("orgs");
            ArrayList<String> organizations = new ArrayList<>();
            StringTokenizer token = new StringTokenizer(allOrgs, ",");
            while (token.hasMoreTokens())
                organizations.add(token.nextToken());

            // Get IP(s) and Certs for each organization -----------------------
            for (int i=0; i<organizations.size(); i++) {
                String current_org = organizations.get(i);
                
                String ip = "", certfile = "", sigs = "", key = "";
                Profile.Section org_ = ini.get(current_org);
                if (org_.containsKey("ip"))
                    ip = org_.get("ip");
                if (org_.containsKey("certfile"))
                    certfile = org_.get("certfile");       
                if (org_.containsKey("sig"))
                    sigs = org_.get("sig");       
                if (org_.containsKey("key"))
                    key = org_.get("key");       

                // Parse IPs
                ArrayList<String> ips = new ArrayList<>();
                StringTokenizer ip_token = new StringTokenizer(ip, ",");
                while (ip_token.hasMoreTokens())
                    ips.add(ip_token.nextToken());
                
                // Read Certificate
                Certificate cert = null;
                if (certfile.length() > 0) {
                    try {
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        BufferedInputStream in = new BufferedInputStream(new FileInputStream(certfile));
                        while (in.available() > 0) {
                            cert = cf.generateCertificate(in);
                        }
                        in.close();            
                    } catch (CertificateException ex) {
                        Logger.getLogger(SigVer.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (FileNotFoundException ex) {
                        Logger.getLogger(SigVer.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IOException ex) {
                        Logger.getLogger(SigVer.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
                
                if (cert!=null) { // Insert into Sig Store, if certificate creation successful
                    for (int j=0; j<ips.size(); j++) {
                        String current_ip = ips.get(j);
                        this.store.put(current_ip, cert);
                        System.out.println("Putting - " + current_ip);
                    }
                }
                if (sigs.length() > 0) { // If there is a signature String, insert it here
                    for (int j=0; j<ips.size(); j++) {
                        String current_ip = ips.get(j);
                        this.sig_store.put(current_ip, sigs);
                    }
                }
                if (key.length() > 0) {
                    for (int j=0; j<ips.size(); j++) {
                        String current_ip = ips.get(j);
                        this.sig_key.put(current_ip, key);
                    }
                }
            }
        }
    }
    
    // Verify that a given IP is in the list of IP addresses (from Ini file)
    public boolean IPCheck(String ip) {
        boolean result = false;
 
        if (ip==null && this.store.containsKey("default"))
            ip = "default"; // TEST
        result = this.store.containsKey(ip); // Has the IP been specified in the Ini file?
        EgaSecureAccessService.log("IP Check for: " + ip + ": " + result);
        System.out.println("IP Check for: " + ip + ": " + result);
        
        return result;
    }
    
    // Verify the signature for a given set of data, where the verification is based on IP
    // (each allowed client has an associated IP and public key on (Ini) file)
    public boolean SigAccessVerification(String data, String signature, String ip, String time) {
        boolean result = false;
        if (ip==null && this.store.containsKey("default"))
            ip="default";
        
        byte[] certdata = Base64.getDecoder().decode(signature);
        
        // Build the signed content from the request body
        String signed = data;
        
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(this.store.get(ip)); // Certificate based on IP
            sig.update(signed.getBytes());
            
            result = sig.verify(certdata);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(SigVer.class.getName()).log(Level.SEVERE, null, ex);
        }

        return result;        
    }
    
    public String getSig(String ip) {
        if (ip==null && this.store.containsKey("default"))
            ip="default";
        return this.sig_store.get(ip);
    }

    public String getKey(String ip) {
        if (ip==null && this.store.containsKey("default"))
            ip="default";
        return this.sig_key.get(ip);
    }
}
