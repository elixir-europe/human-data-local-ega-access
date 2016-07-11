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

package uk.ac.embl.ebi.ega.accessservice;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.handler.traffic.GlobalTrafficShapingHandler;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import java.io.File;
import java.io.FileInputStream;
import java.lang.management.ManagementFactory;
import java.net.URLEncoder;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import net.jodah.expiringmap.ExpiringMap;
import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.concurrent.SubjectAwareExecutorService;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.util.Factory;
import org.slf4j.LoggerFactory;
import sun.misc.BASE64Encoder;
import uk.ac.embl.ebi.ega.accessservice.endpoints.AppService;
import uk.ac.embl.ebi.ega.accessservice.endpoints.DatasetService;
import uk.ac.embl.ebi.ega.accessservice.endpoints.FileService;
import uk.ac.embl.ebi.ega.accessservice.endpoints.GlobusService;
import uk.ac.embl.ebi.ega.accessservice.endpoints.RequestService;
import uk.ac.embl.ebi.ega.accessservice.endpoints.SAML2Service;
import uk.ac.embl.ebi.ega.accessservice.endpoints.Service;
import uk.ac.embl.ebi.ega.accessservice.endpoints.StatService;
import uk.ac.embl.ebi.ega.accessservice.endpoints.UserService;
import uk.ac.embl.ebi.ega.accessservice.utils.Dailylog;
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

/**
 *
 * @author asenf
 */
public class EgaSecureAccessService {

    private static boolean SSL = false;
    private static int port = 9220;
    public static boolean testMode = false;
    public static String path = "";
    private static String configlog = "http://localhost:9228/"; 

    private static Dailylog dailylog;
    
    // Testing only
    private static String[] testuser = null;
    public static PublicKey thePk;
    
    // Signature Verification
    private SigVer sig;
    
    // Shutdown process: Wait until current operations complete
    static volatile boolean keepRunning = true;

    // Executors and traffic counter
    private final DefaultEventExecutorGroup l, s, r; // l = long, s = short, r = request
    private final ScheduledExecutorService executor;
    private final GlobalTrafficShapingHandler globalTrafficShapingHandler;
    
    // Shiro Related
    private static final transient org.slf4j.Logger log = LoggerFactory.getLogger(EgaSecureAccessService.class);    
    
    // IP Freq Counter
    private Random rnd = new Random();
    private Map<String, String> map;

    public EgaSecureAccessService(int port, int cores) {
        EgaSecureAccessService.port = port;

        // Create Security Manager from shiro.ini config file
        Factory<org.apache.shiro.mgt.SecurityManager> factory = new IniSecurityManagerFactory(path + "shiro.ini");
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        
        // Load Ini file (Whitelist & Keys)
        this.sig = new SigVer(path + "certs.ini");        
        
        // Executors
        this.l = new DefaultEventExecutorGroup(cores * 4);
        this.s = new DefaultEventExecutorGroup(cores);
        this.r = new DefaultEventExecutorGroup(cores * 4);
        
        // Traffic Shaping Handler already created
        this.executor = Executors.newScheduledThreadPool(cores);
        this.globalTrafficShapingHandler = new GlobalTrafficShapingHandler(executor, cores);
        this.globalTrafficShapingHandler.trafficCounter().configure(10000); // ??
        
        // Initialize freq counter - expiring after 30 (28) seconds
        map = ExpiringMap.builder()
          .expiration(28, TimeUnit.SECONDS)
          .build();
    }

    public synchronized void putMap(String ip) {
        try {
            String key = String.valueOf(rnd.nextDouble());
            map.put(key, ip);
        } catch (java.util.ConcurrentModificationException ex) {;}
    }
    
    public synchronized int getMap(String ip) {
        int count = 0;
       
        try {
            for (Object o : map.keySet()) {
                if (o!=null && map.get(o).equals(ip)) {
                    count++;
                }
            }
        } catch (java.util.ConcurrentModificationException ex) {;}
        return count;        
    }
   
    public void run(HashMap<String, Service> mappings) throws Exception {
        // Configure SSL.
        final SslContext sslCtx;
        if (SSL) {
            SelfSignedCertificate ssc = new SelfSignedCertificate(); // DEVELOPMENT
            sslCtx = SslContext.newServerContext(SslProvider.JDK, ssc.certificate(), ssc.privateKey());
        } else {
            sslCtx = null;
        }
        
        // Configure Executor Services - based on CPU cores available
        int cores = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(cores*4);
        // Necessary so that Shiro can handle sessions properly
        ExecutorService useThis = new SubjectAwareExecutorService(executor);
        EventLoopGroup bossGroup = new NioEventLoopGroup();
        EventLoopGroup workerGroup = new NioEventLoopGroup((cores*4), useThis);
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
             .channel(NioServerSocketChannel.class)
             //.handler(new LoggingHandler(LogLevel.INFO))
             .childHandler(new EgaSecureAccessServiceInitializer(sslCtx, mappings, sig, 
                     this.l, this.s, this.r, this.globalTrafficShapingHandler, this));

            Channel ch = b.bind(port).sync().channel();

            System.err.println("Open your web browser and navigate to " +
                    (SSL? "https" : "http") + "://127.0.0.1:" + port + '/');

            if (testMode)
                testMe();
        
            ch.closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }

    // GET - Traffic Information
    public String getTransferString() {
        return this.globalTrafficShapingHandler.trafficCounter().toString();
    }
    public JSONObject getTransfer() {
        JSONObject traffic = new JSONObject();
        
        try {
            traffic.put("checkInterval", this.globalTrafficShapingHandler.trafficCounter().checkInterval());

            // Add more...
            
        } catch (JSONException ex) {;}
        
        return traffic;
    }
    
    /**
     * @param args the command line arguments
     * 
     * Parameters: port number (default 9120)
     *      -p port : server port (default 9120)
     *      -l path : path to ini file. default: . (local dir)
     *      -t user:password : testMe - run self-test (using specified user/password), then exit
     */
    public static void main(String[] args) {
        String p = "9220"; int pi = 9220;
        String testup = "";

        final Thread mainThread = Thread.currentThread();
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                keepRunning = false;
//                try {
//                    mainThread.join();
//                } catch (InterruptedException ex) {;}

                System.out.println("Shutdown!!");
            }
        });

        int cores = Runtime.getRuntime().availableProcessors();

        Options options = new Options();

        options.addOption("p", true, "port");        
        options.addOption("l", true, "path");   
        options.addOption("cl", true, "configUrl");        
        options.addOption("t", true, "testMe");        
        options.addOption("s", false, "SSL");        
        
        CommandLineParser parser = new BasicParser();
        try {        
            CommandLine cmd = parser.parse( options, args);
            
            if (cmd.hasOption("p"))
                p = cmd.getOptionValue("p");
            if (cmd.hasOption("l"))
                EgaSecureAccessService.path = cmd.getOptionValue("l");
            if (cmd.hasOption("cl"))
                EgaSecureAccessService.configlog = cmd.getOptionValue("cl");
            if (cmd.hasOption("t")) {
                EgaSecureAccessService.testMode = true;
                testup = cmd.getOptionValue("t");
                EgaSecureAccessService.testuser = testup.split(":");
            }
            if (cmd.hasOption("s"))
                EgaSecureAccessService.SSL = true;
            
            pi = Integer.parseInt(p);
        } catch (ParseException ex) {
            System.out.println("Unrecognized Parameter. Use '-p'  '-t'.");
            Logger.getLogger(EgaSecureAccessService.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Add Service Endpoints
        DatasetService datasetService = new DatasetService();
        FileService fileService = new FileService();
        RequestService requestService = new RequestService();
        UserService userService = new UserService();
        StatService statService = new StatService();
        AppService appService = new AppService();
        GlobusService globusService = new GlobusService();
        SAML2Service saml2Service = new SAML2Service();
        
        HashMap<String, Service> mappings = new HashMap<>();
        mappings.put("/datasets", datasetService);
        mappings.put("/files", fileService);
        mappings.put("/requests", requestService);
        mappings.put("/users", userService);
        mappings.put("/stats", statService);
        mappings.put("/apps", appService);
        mappings.put("/globus", globusService);
        
        // Set up Log File
        if (!EgaSecureAccessService.testMode)
            EgaSecureAccessService.dailylog = new Dailylog("access");
                
        // Start and run the server
        try {
            new EgaSecureAccessService(pi, cores).run(mappings);
        } catch (Exception ex) {
            Logger.getLogger(EgaSecureAccessService.class.getName()).log(Level.SEVERE, null, ex);
        }        
    }
    
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    public static void log(String text) { // Log to text file, daily
        if (EgaSecureAccessService.dailylog != null) {
            String text_ = text;
            if (text_.toLowerCase().contains("pass")) {
                text_ = text_.substring(0, text.toLowerCase().indexOf("pass"));
            }
            EgaSecureAccessService.dailylog.log(text_);
        }
    }
    
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------

    public static String getServer(String type) {
        String result = null;
        
        String svc = type.toLowerCase().trim();
        if (!svc.equals("data"))
            return result;
        
        Resty r = new Resty(new RestyTimeOutOption(2000,2000));
        int countdown = 4;
        while (result==null || !(result.toLowerCase().startsWith("http")) && countdown-- > 0) {
            try {
                // Get Info from Config (Which must run on Localhost, for now)
                String sql = EgaSecureAccessService.configlog + "ega/rest/configlog/v2/services/" + svc;
                //String sql = "http://pg-ega-pro-05.ebi.ac.uk:9228/ega/rest/configlog/v2/services/" + svc;
                JSONResource json = r.json(sql);
                JSONObject jobj = (JSONObject) json.get("response");

                JSONArray jsonarr1 = (JSONArray)jobj.get("result");
                if (jsonarr1.length() >=1 ) {
                    JSONObject jobj2 = (JSONObject)jsonarr1.get(0); // There should ever only be 1

                    // Get load-balanced Data Service URL
                    String protocol = jobj2.getString("protocol");
                    while (protocol.endsWith(":")) protocol = protocol.substring(0, protocol.length()-1);
                    result = protocol + "://" + 
                                jobj2.getString("server") + ":" + 
                                jobj2.getString("port") + "/" + 
                                jobj2.getString("baseUrl") +
                                jobj2.getString("name") + "/" + 
                                jobj2.getString("version");
                }
            } catch (Throwable t) {
                System.out.println(t.getLocalizedMessage());
            }
            
            if (result==null || !(result.toLowerCase().startsWith("http"))) {
                Random rnd = new Random();
                try {
                    Thread.sleep(rnd.nextInt(2000));
                } catch (InterruptedException ex) {;}
            }
        }
 
        System.out.println("Service: " + result);
        return result;
    }
    
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    public static double getSystemCpuLoad() throws MalformedObjectNameException, ReflectionException, InstanceNotFoundException {

        MBeanServer mbs    = ManagementFactory.getPlatformMBeanServer();
        ObjectName name    = ObjectName.getInstance("java.lang:type=OperatingSystem");
        AttributeList list = mbs.getAttributes(name, new String[]{ "SystemCpuLoad" });

        if (list.isEmpty())     return Double.NaN;

        Attribute att = (Attribute)list.get(0);
        Double value  = (Double)att.getValue();

        if (value == -1.0)      return Double.NaN;  // usually takes a couple of seconds before we get real values

        return ((int)(value * 1000) / 10.0);        // returns a percentage value with 1 decimal point precision
    }
    
    
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // Self-Test of functionality provided in this server
    private void testMe() throws Exception {
        // Wait until server has started up
        Thread.sleep(2000);
        
        EgaSecureAccessServiceHandler.load_ceiling = 100.0; // ignore server loads for testing
        Resty r = new Resty(new RestyTimeOutOption(8000, 4000));
        
        if (EgaSecureAccessService.testuser != null) { // User is required
            //appTests(r, sig);
            //System.exit(999);
            String sId = "";
            
            // Test 1: Successful AuTN (Parameter)
            System.out.println("Testing Parameter Success:");
            String user = URLEncoder.encode(EgaSecureAccessService.testuser[0], "UTF-8");
            String params = URLEncoder.encode(EgaSecureAccessService.testuser[1], "UTF-8");

            String query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/users/" + user + "?pass=" + params;
            JSONResource json = r.json(query);
            JSONObject jobj = (JSONObject) json.get("response");
            JSONArray jsonarr = (JSONArray)jobj.get("result");
            System.out.println("Result Length (always 1): " + jsonarr.length());
            for (int i=0; i<jsonarr.length(); i++) {
                String request = jsonarr.getString(i);
                System.out.println("Result "+i+": " + request);
            }
            if (jsonarr.length()==2)
                sId = jsonarr.getString(1);
            System.out.println("SessionID: " + sId);
            
            // -----------------------------------------------------------------
            // Perform usability tests, before testing other autn calls --------
            
            // List Tests (Datasets, Files) - returns a file/dataset for the specified user for later tests
            String[] data = listTests(r, sId); // OK
            
            data[0] = "EGAD00000000001"; // "EGAD00010000805";
            //for (int i=0; i<1000; i++)
                requestTests(r, data[0], data[1], sId); // Make a request, List a Request, Delete a request
            
            appTests(r, sig);
            
            // -----------------------------------------------------------------
            // -----------------------------------------------------------------
            query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/users/logout";
            json = r.json(query);

            // Test 2: Successful AuTN (Basic Auth)
            System.out.println("Testing Basic AuTN Success:");
            String userpass = EgaSecureAccessService.testuser[0]+":"+EgaSecureAccessService.testuser[1];
            String basicAuth = "Basic " + Base64.getEncoder().encodeToString(userpass.getBytes());
            r.alwaysSend("Authorization", basicAuth);            
            query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/users/login";
            json = r.json(query);
            jobj = (JSONObject) json.get("response");
            jsonarr = (JSONArray)jobj.get("result");
            System.out.println("Result Length (always 1): " + jsonarr.length());
            for (int i=0; i<jsonarr.length(); i++) {
                String request = jsonarr.getString(i);
                System.out.println("Result "+i+": " + request);
            }
            query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/users/logout";
            json = r.json(query);
            
            // Test 3: Successful AuTN (POST)
            System.out.println("Testing POST Success (standard):");
            r = new Resty();
            JSONObject json1 = new JSONObject();
            json1.put("username", user);
            json1.put("password", params);            
            query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/users/login";
            json = r.json(query, form( data("loginrequest", content(json1))) );
            jobj = (JSONObject) json.get("response");
            jsonarr = (JSONArray)jobj.get("result");
            System.out.println("Result Length (always 1): " + jsonarr.length());
            for (int i=0; i<jsonarr.length(); i++) {
                String request = jsonarr.getString(i);
                System.out.println("Result "+i+": " + request);
            }
            query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/users/logout";
            json = r.json(query);
            
            // Test 4: Failed AuTN (Parameter)
            System.out.println("Testing Parameter Fail:");
            r = new Resty();
            user = URLEncoder.encode("random@random", "UTF-8");
            params = "pass=" + URLEncoder.encode("random%", "UTF-8");
            query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/users/" + user + "?" + params;
            json = r.json(query);
            jobj = (JSONObject) json.get("response");
            jsonarr = (JSONArray)jobj.get("result");
            System.out.println("Result Length (always 1): " + jsonarr.length());
            for (int i=0; i<jsonarr.length(); i++) {
                String request = jsonarr.getString(i);
                System.out.println("Result "+i+": " + request);
            }
            
            // Test 5: Failed AuTN (Basic)
            System.out.println("Testing Basic AuTN Fail:");
            userpass = "random@random"+":"+"random%";
            basicAuth = "Basic " + Base64.getEncoder().encodeToString(userpass.getBytes());
            r.alwaysSend("Authorization", basicAuth);

            query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/users/login";
            json = r.json(query);
            jobj = (JSONObject) json.get("response");
            jsonarr = (JSONArray)jobj.get("result");
            System.out.println("Result Length (always 1): " + jsonarr.length());
            for (int i=0; i<jsonarr.length(); i++) {
                String request = jsonarr.getString(i);
                System.out.println("Result "+i+": " + request);
            }
            
            // Test 6: Failed AuTN (POST)
            System.out.println("Testing POST Fail:");
            r = new Resty();
            json1 = new JSONObject();
            json1.put("username", user);
            json1.put("password", params);
            
            query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/users/login";
            json = r.json(query, form( data("loginrequest", content(json1))) );
            jobj = (JSONObject) json.get("response");
            jsonarr = (JSONArray)jobj.get("result");
            System.out.println("Result Length (always 1): " + jsonarr.length());
            for (int i=0; i<jsonarr.length(); i++) {
                String request = jsonarr.getString(i);
                System.out.println("Result "+i+": " + request);
            }
            
            // Test 7: Stats (load)
            r = new Resty();
            query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/stats/load";
            json = r.json(query);
            jobj = (JSONObject) json.get("response");
            jsonarr = (JSONArray)jobj.get("result");
            System.out.println("Loads (should be 1): " + jsonarr.length());
            for (int i=0; i<jsonarr.length(); i++) {
                String request = jsonarr.getString(i);
                System.out.println("Load "+i+": " + request);
            }
        } else {
            System.out.println("Usage: '-t {username}:{password} for valid user.");
        }
        
        System.exit(100); // End the server after self test is complete
    }
    
    // Test List URLs
    private static String[] listTests(Resty r, String sId) {
        String datasetID = "", fileID = "";
        
        try {
            // Test listing Datasets -----------
            String query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/datasets";
            JSONResource json = r.json(query + "?session=" + sId);
            JSONObject jobj = (JSONObject) json.get("response");
            JSONArray jsonarr = (JSONArray)jobj.get("result");
            System.out.println("Result Length (always 1): " + jsonarr.length());
            ArrayList<String> datasets = new ArrayList<>();
            for (int i=0; i<jsonarr.length(); i++) {
                String dataset = jsonarr.getString(i);
                datasets.add(dataset);
                System.out.println("Result "+i+": " + dataset);
            }
            
            // Test listing Files in Datasets -----------
            // Test 2: List all files in all datasets
            for (String dataset : datasets) {
                String query2 = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/datasets/" + dataset + "/files";
                JSONResource json2 = r.json(query2 + "?session=" + sId);
                try {
                    JSONObject jobj2 = (JSONObject) json2.get("response");
                    JSONArray jsonarr2 = (JSONArray)jobj2.get("result");
                    System.out.println("Files in Datasets " + dataset + ": " + jsonarr2.length());
                    // Print first 5 files
                    if (jsonarr2!=null && jsonarr2.length()>0) {
                        for (int j=0; j<(jsonarr2.length()>5?5:jsonarr2.length()); j++) {
                            JSONObject jsonObject2 = jsonarr2.getJSONObject(j);
                            System.out.println("   " + j + ": " + jsonObject2.getString("fileID") + " :: " + jsonObject2.getString("fileName") + " :: " + jsonObject2.getLong("fileSize") + " :: " + jsonObject2.getString("fileStatus"));
                            
                            // Save first successful data element
                            if (datasetID.length() == 0)
                                datasetID = dataset;
                            if (fileID.length() == 0)
                                fileID = jsonObject2.getString("fileID");
                        }
                    }
                    
                } catch (Throwable t) {
                    System.out.println("Error (List Files): " + query2);
                }
            }

            // Test listing one particular File -----------
            String query3 = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/files/" + fileID;
            JSONResource json3 = r.json(query3 + "?session=" + sId);
            try {
                JSONObject jobj3 = (JSONObject) json3.get("response");
                JSONArray jsonarr3 = (JSONArray)jobj3.get("result");
                System.out.println("File " + fileID + " in Datasets " + datasetID + ": " + jsonarr3.length());
                
            } catch (Throwable t) {
                System.out.println("Error (List File): " + query3 + " :: " + t.getLocalizedMessage());
            }

        } catch (Exception ex) {
            Logger.getLogger(EgaSecureAccessService.class.getName()).log(Level.SEVERE, null, ex);
        }

        // Return selected data for future tests
        String[] result = new String[] {datasetID, fileID};
        return result;
    }
    
    private static void requestTests(Resty r, String datasetID, String fileID, String sId) {
        try {
            // Test making a Datasets Request -----------
            System.out.println("Requesting a Dataset:");
            String query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/requests/new/datasets/" + datasetID;
            
            JSONObject json1 = new JSONObject();
            json1.put("id", datasetID);
            json1.put("rekey", "abc");
            json1.put("downloadType", "STREAM");
            json1.put("descriptor", "AccessTestRequest");

            System.out.println("Query (1): " + query);
            JSONResource json = r.json(query + "?session=" + sId, form( data("downloadrequest", content(json1))) );
            JSONObject jobj = (JSONObject) json.get("response");
System.out.println(jobj.toString());
            JSONArray jsonarr = (JSONArray)jobj.get("result");
            System.out.println("Result Length (always 1): " + jsonarr.length());
            for (int i=0; i<jsonarr.length(); i++)
                System.out.println(" ---- " + jsonarr.get(i).toString());
            
            // Test making a File Request ---------------
            System.out.println("Requesting a File:");
            String query_file = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/requests/new/files/" + fileID;
            
            JSONObject json2 = new JSONObject();
            json2.put("id", fileID);
            json2.put("rekey", "abc");
            json2.put("downloadType", "STREAM");
            json2.put("descriptor", "AccessTestRequestFile");
            
            System.out.println("Query (2): " + query);
            JSONResource json_file = r.json(query_file + "?session=" + sId, form( data("downloadrequest", content(json2))) );
            JSONObject jobj_file = (JSONObject) json_file.get("response");
System.out.println(jobj_file.toString());
            JSONArray jsonarr_file = (JSONArray)jobj_file.get("result");
            System.out.println("Result Length (always 1): " + jsonarr_file.length());
            for (int i=0; i<jsonarr_file.length(); i++)
                System.out.println(" ---- " + jsonarr_file.get(i).toString());
                        
            // Test listing Requests
            System.out.println("Listing Requests:");
            String query_requests = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/requests/";
            JSONResource json_requests = r.json(query_requests + "?session=" + sId);
            JSONObject jobj_requests = (JSONObject) json_requests.get("response");
            JSONArray jsonarr_requests = (JSONArray)jobj_requests.get("result");
            System.out.println("Result Length (num of requests): " + jsonarr_requests.length());
            
            // Test listing a Request
            System.out.println("Listing a Request:");
            String query_request = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/requests/" + "AccessTestRequestFile";
            JSONResource json_request = r.json(query_request + "?session=" + sId);
            JSONObject jobj_request = (JSONObject) json_request.get("response");
            JSONArray jsonarr_request = (JSONArray)jobj_request.get("result");
            System.out.println("Result Length (num of requests): " + jsonarr_request.length());
            
            String ticket = "";
            for (int i=0; i<jsonarr_request.length(); i++) {
                JSONObject ticket_ = (JSONObject) jsonarr_request.get(i);
                if (ticket.length() == 0)
                    ticket = ticket_.getString("ticket");
                System.out.println("Ticket: " + ticket_.getString("ticket") + ", Label: " + ticket_.getString("label"));
            }

            // Test listing a Ticket
            System.out.println("Listing a Ticket:");
            String query_ticket = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/requests/ticket/" + ticket;
            JSONResource json_ticket = r.json(query_ticket + "?session=" + sId);
            JSONObject jobj_ticket = (JSONObject) json_ticket.get("response");
            JSONArray jsonarr_ticket = (JSONArray)jobj_ticket.get("result");
            System.out.println("Result Length (should be 1): " + jsonarr_ticket.length());
            for (int i=0; i<jsonarr_ticket.length(); i++) {
                System.out.println(jsonarr_ticket.get(i).toString());
            }
            
            // Test deleting a Request ------------------
            String query_delete = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/requests/delete/AccessTestRequest";

            JSONResource json_delete = r.json(query_delete + "?session=" + sId, delete() );
            JSONObject jobj_delete = (JSONObject) json_delete.get("response");
            JSONArray jsonarr_delete = (JSONArray)jobj_delete.get("result");
            System.out.println("Result Length Delete Request (always 1): " + jsonarr_delete.length());
            if (jsonarr_delete.length() > 0) {
                System.out.println(jsonarr_delete.getString(0));
            }

            // Test deleting a Ticket ------------------
            String query_delete_ticket = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/requests/delete/AccessTestRequestFile/" + ticket;

            JSONResource json_delete_ticket = r.json(query_delete_ticket + "?session=" + sId, delete() );
            JSONObject jobj_delete_ticket = (JSONObject) json_delete_ticket.get("response");
            JSONArray jsonarr_delete_ticket = (JSONArray)jobj_delete_ticket.get("result");
            System.out.println("Result Length Delete Ticket (always 1): " + jsonarr_delete_ticket.length());

            // Test deleting a Ticket ------------------
            //String query_delete_ticket_ = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/requests/ticket/delete/" + ticket;

            //JSONResource json_delete_ticket_ = r.json(query_delete_ticket_, delete() );
            //JSONObject jobj_delete_ticket_ = (JSONObject) json_delete_ticket_.get("response");
            //JSONArray jsonarr_delete_ticket_ = (JSONArray)jobj_delete_ticket_.get("result");
            //System.out.println("Result Length Delete Ticket (always 1): " + jsonarr_delete_ticket_.length());
        } catch (Exception ex) {
            Logger.getLogger(EgaSecureAccessService.class.getName()).log(Level.SEVERE, null, ex);
        }
    }    

    private static void appTests(Resty r, SigVer sig) {
        try {
            System.out.println("AppTest --");
            
            // NOT UPDATED FOR LOCAL EGA
            
            // Load Certificate
            KeyStore caKs = KeyStore.getInstance(KeyStore.getDefaultType());
            caKs.load(new FileInputStream(new File("keystore.jks")), "password".toCharArray());
            Key key = caKs.getKey("selfsigned", "password".toCharArray());
            RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) key;

            // -----------------------------------------------------------------
            // Test: POST dl request as an authorized app
            String query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/apps/requests/new";            
            JSONObject json1 = new JSONObject();
            json1.put("username", "..");
            json1.put("userip", "127.0.0.1");
            json1.put("dataset", "EGAD00010000214");
            json1.put("fileid", "EGAF00000102981,EGAF00000102982");
            json1.put("label", "appPostTest");
            json1.put("rekey", "abc");

            // Sign Request
            String signature = "";
            signature += "username" + ".." + "userip" + "127.0.0.1" + "dataset" + "EGAD00010000214" + "fileid" + "EGAF00000102981,EGAF00000102982" + "label" + "appPostTest" + "rekey" + "abc";
            try { // Set up Signature
                Signature dsa = Signature.getInstance("SHA256withRSA");
                dsa.initSign(privKey);
                dsa.update(signature.getBytes());
                byte[] sign = dsa.sign();
                BASE64Encoder encoder=new BASE64Encoder();
                signature = encoder.encode(sign).replaceAll("\n", "");
            } catch (Throwable t) {
                System.out.println(t.toString());
            }            
            
            r.alwaysSend("X-Client-Sig", signature);
            JSONResource json = r.json(query, form( data("apprequest", content(json1))) );
            
            JSONObject jbj = (JSONObject) json.get("response");
            System.out.println("------");
            System.out.println(jbj.toString());
            System.out.println("------");
            JSONArray jsnarr = (JSONArray)jbj.get("result");
            System.out.println("Result Length (always 1): " + jsnarr.length());
            for (int i=0; i<jsnarr.length(); i++) {
                String request = jsnarr.getString(i);
                System.out.println("Result "+i+": " + request);
            }
            
            // -----------------------------------------------------------------
            // Test: List request with an authorized App - using previous as example
            System.out.println("Testing App Interface");
            //query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/apps/requests/" + "asenf@ebi.ac.uk" + "/" + "testGlob";
            query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/apps/requests/" + "asenf@ebi.ac.uk" + "/" + "appPostTest";

            //String signature = sig.getSig("127.0.0.1");
            //signature = "username" + ".." + "request" + "testGlob";
            signature = "username" + ".." + "request" + "appPostTest";
            try { // Set up Signature
                Signature dsa = Signature.getInstance("SHA256withRSA");
                dsa.initSign(privKey);
                dsa.update(signature.getBytes());
                byte[] sign = dsa.sign();
                BASE64Encoder encoder=new BASE64Encoder();
                signature = encoder.encode(sign).replaceAll("\n", "");
            } catch (Throwable t) {
                System.out.println(t.toString());
            }            
            
            r.alwaysSend("X-Client-Sig", signature);
            JSONResource json_ = r.json(query);
            
            JSONObject jbj_ = (JSONObject) json_.get("response");
            JSONArray jsnarr_ = (JSONArray)jbj_.get("result");
            System.out.println("Result Length (always 1): " + jsnarr_.length());
            
            EgaTicket[] result = new EgaTicket[jsnarr_.length()];
            for (int i=0; i<jsnarr_.length(); i++) {
                JSONObject oneTicket = (JSONObject) jsnarr_.get(i);

                String ticket = oneTicket.getString("ticket");
                String label = oneTicket.getString("label");
                String fileID = oneTicket.getString("fileID");
                String fileType = oneTicket.getString("fileType");
                String fileSize = oneTicket.getString("fileSize");
                String fileName = oneTicket.getString("fileName");
                String encryptionKey = oneTicket.getString("encryptionKey");
                String transferType = oneTicket.getString("transferType");
                String transferTarget = oneTicket.getString("transferTarget");
                String user = oneTicket.getString("user");

                result[i] = new EgaTicket(ticket, label, fileID, fileType, fileSize, fileName, encryptionKey, transferType, transferTarget, user);
            }

            String ticket_ = "";
            for (int i=0; i<result.length; i++) {
                System.out.println("Label: " + result[i].getLabel());
                System.out.println("Ticket: " + result[i].getTicket());
                
                if (ticket_.length() == 0)
                    ticket_ = result[i].getTicket();
            }
            
            // Test: List request with an authorized App - using previous as example
            System.out.println("Testing DS Access for a Ticket");
            //query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/apps/tickets/" + "cb5ae6ba-de6f-467a-bab2-4c27e57230ee" + "?key=gw6tUg4g1vs7gg";
            query = "http://localhost:" + EgaSecureAccessService.port + "/ega/rest/access/v2/apps/tickets/" + ticket_ + "?key=" + sig.getKey("127.0.0.1"); //gw6tUg4g1vs7gg";
            r = new Resty();
            JSONResource json_d = r.json(query);
            
            JSONObject jbj_d = (JSONObject) json_d.get("response");
            JSONArray jsnarr_d = (JSONArray)jbj_d.get("result");
            System.out.println("Result Length (always 1): " + jsnarr_d.length());
            
            EgaTicket[] resultd = new EgaTicket[jsnarr_d.length()];
            for (int i=0; i<jsnarr_d.length(); i++) {
                JSONObject oneTicket = (JSONObject) jsnarr_d.get(i);

                String ticket = oneTicket.getString("ticket");
                String label = oneTicket.getString("label");
                String fileID = oneTicket.getString("fileID");
                String fileType = oneTicket.getString("fileType");
                String fileSize = oneTicket.getString("fileSize");
                String fileName = oneTicket.getString("fileName");
                String encryptionKey = oneTicket.getString("encryptionKey");
                String transferType = oneTicket.getString("transferType");
                String transferTarget = oneTicket.getString("transferTarget");
                String user = oneTicket.getString("user");

                resultd[i] = new EgaTicket(ticket, label, fileID, fileType, fileSize, fileName, encryptionKey, transferType, transferTarget, user);
            }
            
            for (int i=0; i<resultd.length; i++) {
                System.out.println("Label: " + resultd[i].getLabel());
                System.out.println("Ticket: " + resultd[i].getTicket());
                System.out.println("File: " + resultd[i].getFileName());
            }
            
        } catch (Exception ex) {
            Logger.getLogger(EgaSecureAccessService.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
    }    
}
