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

// DEMO CODE

package uk.ac.embl.ebi.ega.accessservice.utils;

import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.X509Certificate;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;
 
public class MyProvider extends Provider
{
  public MyProvider()
  {
    super("MyProvider", 1.0, "Trust certificates");
    put("TrustManagerFactory.TrustAllCertificates", MyTrustManagerFactory.class.getName());
  }
 
  protected static class MyTrustManagerFactory extends TrustManagerFactorySpi
  {
    public MyTrustManagerFactory()
      {}
    protected void engineInit( KeyStore keystore )
      {}
    protected void engineInit(ManagerFactoryParameters mgrparams )
      {}
    protected TrustManager[] engineGetTrustManagers()
    {
      return new TrustManager[] {new MyX509TrustManager()};
    }
  }
 
  protected static class MyX509TrustManager implements X509TrustManager
  {
    public void checkClientTrusted(X509Certificate[] chain, String authType)
      {}
    public void checkServerTrusted(X509Certificate[] chain, String authType)
      {}
    public X509Certificate[] getAcceptedIssuers()
      { return null; }
  }
 
}