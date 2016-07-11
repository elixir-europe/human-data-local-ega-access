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

/*
 * This class provides responses to REST URLs
 * This service will run ONLY inside the EGA Vault and is not available anywhere else
 * For this reason it uses plain http and no user account information
 *
 * URL Prefix for his server is: /ega/rest/access/v2
 *
 * Resources are:
 *
 * /users/{user}?pass=<pass>        Get User ID via Parameters
 * /users/login                     Get User ID via Basic Auth
 * /users/logout                    Log out session
 * POST /users/login ["loginrequest":{username}{password}]  Get Password via POST
 * /users/login/globus
** /users/login/SAML2               Get Authentication via SAML token (hope to replace the others)
 *
 * /datasets
 * /datasets/{dataset}/files
 *
 * /files/{fileid}
 *
 * /requests
 * /requests/{requestlabel}
 * /requests/{requestlabel}/localize
 * /requests/ticket/{ticket}
 * /requests/ticket/delete/{ticket}
 * /requests/delete/{requestlabel}
 * /requests/delete/{requestlabel}/{ticket}
 * /requests/new/datasets/{datasetid}
 * /requests/new/files/{fileid}
 * * 
 * /stats/load                      Get CPU load of Server
 *
 * ** App Request Endpoints (no valid user context required)
 *
 * /apps/requests/new ["apprequest":{user}{userip}{dataset}{fileid}{label}{rekey}] where fileid is CSV
 * /apps/requests/{user}/{requestlabel}
 * /apps/requests/{user}/{requestlabel}/{ticket}
 * /apps/tickets/{ticket}?key={}
 * 
 * /apps/users/{user_email}/datasets?dac={dac}      -- All Datasets for a User, by DAC
 * /apps/datasets/{dataset_id}/users/               -- All Users for a Dataset
 * /apps/datasets/{dataset_id}/users/{user_email}   -- Yes/No
 * 
 * /globus/{user} [requires oAuth 2.0 token] [data: endpoint, request]
 * 
 */

package uk.ac.embl.ebi.ega.accessservice;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import static io.netty.handler.codec.http.HttpHeaderNames.CONTENT_TYPE;
import io.netty.handler.codec.http.HttpResponseStatus;
import static io.netty.handler.codec.http.HttpResponseStatus.BAD_REQUEST;
import static io.netty.handler.codec.http.HttpResponseStatus.INTERNAL_SERVER_ERROR;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http.HttpResponseStatus.SERVICE_UNAVAILABLE;
import static io.netty.handler.codec.http.HttpResponseStatus.UNAUTHORIZED;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;
import io.netty.util.CharsetUtil;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import uk.ac.embl.ebi.ega.accessservice.endpoints.Service;
import uk.ac.embl.ebi.ega.accessservice.utils.MyPipelineUtils;
import uk.ac.embl.ebi.ega.accessservice.utils.SigVer;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;

/**
 *
 * This is unique/exclusive for each connection - place user interaction caches here
 */
public class EgaSecureAccessServiceHandler extends SimpleChannelInboundHandler<FullHttpRequest> { // (1)

    public static final String HTTP_DATE_FORMAT = "EEE, dd MMM yyyy HH:mm:ss zzz";
    public static final String HTTP_DATE_GMT_TIMEZONE = "GMT";
    public static final int HTTP_CACHE_SECONDS = 60;
    
    public static double load_ceiling = 100.0;
    
    // Handle session unique information
    private boolean SSL = false, active = true;
    private final HashMap<String, Service> endpointMappings;
    private final SigVer sig;
    
    // Error information
    private String error_message;
    
    private final EgaSecureAccessService ref;
       
    public EgaSecureAccessServiceHandler(boolean SSL, HashMap<String, Service> mappings, SigVer sig,
                    EgaSecureAccessService ref) throws NoSuchAlgorithmException {
        super();
        this.SSL = SSL;
        this.endpointMappings = mappings;
        this.sig = sig;
        this.ref = ref;
    }

    // *************************************************************************
    // *************************************************************************
    @Override
    public void messageReceived(ChannelHandlerContext ctx, FullHttpRequest request) throws Exception {
        if (ctx==null) return; if (request==null) return; // Don't even proceed in these cases!
        error_message = "0";
        
        // Step 1: Get IP; may be contained in a Header
        String get = request.headers().get("Accept").toString(); // Response Type
        String ip = MyPipelineUtils.getIP(ctx, request);
        error_message = "1";

        // Step 2: Check Request
        HttpResponseStatus checkURL = MyPipelineUtils.checkURL(request);
        if (checkURL != OK) {
            error_message = "Request Verification Error.";
            sendError(ctx, checkURL, get);
            return;
        }
        error_message = "2";
        
        // Step 3: Active for Binary Connections??
        if (!EgaSecureAccessService.keepRunning && !get.contains("application/json")) {
            error_message = "Service shutting down.";
            sendError(ctx, SERVICE_UNAVAILABLE, get); // Service is shutting down
            return;
        }
        error_message = "3";
        
        // Step 4: process the path (1) verify root and service (2) determine function & resource
        String path = MyPipelineUtils.sanitizedUserAction(request);
        ArrayList<String> id = new ArrayList<>();
        String function = MyPipelineUtils.processUserURL(path, id);
        error_message = "4";
        
        // Step 5: for 'apps' endpoint/function, check IP whitelist
System.out.println("Function: " + function);
        boolean allowed = (function.equalsIgnoreCase("/apps"))?this.sig.IPCheck(ip):true;
System.out.println("Allowed? " + allowed);
        if (!allowed) {
            this.error_message = "URL " + path + " not allowed.";
            EgaSecureAccessService.log(this.error_message + " " + ip);
            sendError(ctx, UNAUTHORIZED, get); // If the URL is incorrect...
            return;
        }
        error_message = "5";
        
        // Step 6: Extract any parameters sent with request
        path = MyPipelineUtils.sanitize(request); // Need to get Parameters as well (TODO - optimize)
        Map<String, String> parameters = MyPipelineUtils.getParameters(path);
        parameters.put("ip", ip);
        error_message = "6 " + function;

        // *********************************************************************
        // Map function to endpoint, process request
        JSONObject json = null;
        if (this.endpointMappings.containsKey(function) && allowed) {
            json = this.endpointMappings.get(function).handle(id, parameters, request, sig, ref);
        } else {
            this.error_message = "Error in endpoint " + function;
            sendError(ctx, BAD_REQUEST, get); // If the URL Function is incorrect...
            return;
        }
        error_message = "7";
        // *********************************************************************
        
        // Step 2: Check for auth error (expired session) and log user out!
        JSONObject jsonObject = json.has("header")?json.getJSONObject("header"):null;
        if (jsonObject!=null) {
            //if (jsonObject.getString("code").equals(String.valueOf(UNAUTHORIZED))) {
            if (jsonObject.getString("code").contains(String.valueOf(UNAUTHORIZED))) {
                ensureUserIsLoggedOut();
            }
        } else {
            System.out.println(json.toString());
            //ensureUserIsLoggedOut();
        }
        error_message = "8";
        
        // Step 3: Prepare a response - set content typt to the expected type
        FullHttpResponse response = new DefaultFullHttpResponse(HTTP_1_1, OK);
        StringBuilder buf = new StringBuilder();
        response.headers().set(CONTENT_TYPE, "application/json");
        buf.append(json.toString());
        error_message = "9";
        
        // Step 4: Result has been obtained. Build response and send to requestor
        ByteBuf buffer = Unpooled.copiedBuffer(buf, CharsetUtil.UTF_8);
        response.content().writeBytes(buffer);
        ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        error_message = "10";
        
        // Cleanup
        buffer.release();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        EgaSecureAccessService.log("Exception: (" + error_message + "): " + cause.toString());
        this.error_message = cause.toString();
        if (ctx.channel().isActive()) {
            sendError(ctx, INTERNAL_SERVER_ERROR);
        }
    }
    
    // JSON Version of error messages
    private void sendError(ChannelHandlerContext ctx, HttpResponseStatus status) {
        sendError(ctx, status, "application/json");
    }
    private void sendError(ChannelHandlerContext ctx, HttpResponseStatus status, String get) {
        EgaSecureAccessService.log(status.toString());
        try {
            FullHttpResponse response = new DefaultFullHttpResponse(HTTP_1_1, status);
            JSONObject json = new JSONObject(); // Start out with common JSON Object
            json.put("header", responseHeader(status, error_message)); // Header Section of the response
            json.put("response", error_message);
            
            StringBuilder buf = new StringBuilder();
            response.headers().set(CONTENT_TYPE, "application/json");
            buf.append(json.toString());
            
            ByteBuf buffer = Unpooled.copiedBuffer(buf, CharsetUtil.UTF_8);
            response.content().writeBytes(buffer);
            
            // Close the connection as soon as the error message is sent.
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        } catch (JSONException ex) {
            Logger.getLogger(EgaSecureAccessServiceHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
        
    // Generate JSON Header Section
    private JSONObject responseHeader(HttpResponseStatus status) throws JSONException {
        return responseHeader(status, "");
    }
    private JSONObject responseHeader(HttpResponseStatus status, String error) throws JSONException {
        JSONObject head = new JSONObject();
        
        head.put("apiVersion", "v2");
        head.put("code", String.valueOf(status.code()));
        head.put("service", "access");
        head.put("technicalMessage", "");                   // TODO (future)
        head.put("userMessage", status.reasonPhrase());
        head.put("errorCode", String.valueOf(status.code()));
        head.put("docLink", "http://www.ebi.ac.uk/ega");    // TODO (future)
        head.put("errorStack", error);                     // TODO ??
        
        return head;
    }

    // Logout the user fully before continuing.
    private Subject getSubject()
    {
        Subject currentUser = SecurityUtils.getSubject();// SecurityUtils.getSubject();

        if (currentUser == null)
        {
            currentUser = SecurityUtils.getSubject();
        }

        return currentUser;
    }
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
}

