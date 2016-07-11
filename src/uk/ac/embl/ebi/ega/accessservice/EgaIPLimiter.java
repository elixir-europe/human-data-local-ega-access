/*
 * Copyright 2016 EMBL-EBI
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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerAdapter;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import static io.netty.handler.codec.http.HttpHeaderNames.CONTENT_TYPE;
import io.netty.handler.codec.http.HttpResponseStatus;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;
import io.netty.util.CharsetUtil;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import uk.ac.embl.ebi.ega.accessservice.utils.MyPipelineUtils;
import us.monoid.json.JSONArray;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;
import us.monoid.json.XML;

/**
 *
 * @author asenf
 */
public class EgaIPLimiter extends ChannelHandlerAdapter {
    private EgaSecureAccessService ref;
    
    private static HttpResponseStatus REQUEST_ERROR = new HttpResponseStatus(580, "Error Getting Request Header");

    private String error_message = "";
    
    public EgaIPLimiter(EgaSecureAccessService ref) {
        this.ref = ref;
    }
    
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object i) {
        // Step 1: Verify that there is a channel and request
        if (ctx==null) return; if (i==null) return; // Don't even proceed in these cases!
        FullHttpRequest request = (FullHttpRequest)i;

        // Additional step, 1.5: Get IP
        String get = request.headers().get("Accept").toString(); // Response Type
        String ip = MyPipelineUtils.getIP(ctx, request);
        System.out.println("IP: " + ip);
        
        // *********************************************************************
        // * Limit Access based on Frequency of IP in last 30 seconds - except for DS
        // *********************************************************************        
        this.ref.putMap(ip);
        int cnt_30_sec = this.ref.getMap(ip);
        boolean local = (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("193."));
        System.out.println("IP: " + ip + " 30 Second count: " + cnt_30_sec + " local? " + local);
        
        if (cnt_30_sec > 30 && !local) {
            sendError(ctx, HttpResponseStatus.TOO_MANY_REQUESTS);
            return;
        } else {
            ChannelPipeline p = ctx.pipeline(); // necessary?
            p.remove(this);                     // necessary?
            ctx.fireChannelRead(i);
        }
    }

    private void sendError(ChannelHandlerContext ctx, HttpResponseStatus status) {
        sendError(ctx, status, "application/json");
    }
    private void sendError(ChannelHandlerContext ctx, HttpResponseStatus status, String get) {
        EgaSecureAccessService.log(status.toString());
        try {
            FullHttpResponse response = new DefaultFullHttpResponse(HTTP_1_1, status);
            JSONObject json = new JSONObject(); // Start out with common JSON Object
            json.put("header", responseHeader(status)); // Header Section of the response
            json.put("response", "null"); // ??
            
            StringBuilder buf = new StringBuilder();
            if (get.contains("application/json") || get.contains("application/octet-stream")) { // Format list of values as JSON
                response.headers().set(CONTENT_TYPE, "application/json");
                buf.append(json.toString());
            } else if (get.contains("xml")) { // Format list of values as XML
                response.headers().set(CONTENT_TYPE, "application/xml");
                String xml = XML.toString(json);
                buf.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                buf.append("<Result>");
                buf.append(xml);
                buf.append("</Result>");
            }
            
            ByteBuf buffer = Unpooled.copiedBuffer(buf, CharsetUtil.UTF_8);
            response.content().writeBytes(buffer);
            
            // Close the connection as soon as the error message is sent.
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        } catch (JSONException ex) {
            Logger.getLogger(EgaSecureAccessService.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    // Generate JSON Header Section
    private JSONObject responseHeader(HttpResponseStatus status) throws JSONException {
        return responseHeader(status, error_message);
    }
    private JSONObject responseHeader(HttpResponseStatus status, String error) throws JSONException {
        JSONObject head = new JSONObject();
        
        head.put("apiVersion", "v2");
        head.put("code", String.valueOf(status.code()));
        head.put("service", "access");
        head.put("technicalMessage", "EgaIPLimiter");
        head.put("userMessage", status.reasonPhrase());
        head.put("errorCode", String.valueOf(status.code()));
        head.put("docLink", "http://www.ebi.ac.uk/ega");
        head.put("errorStack", error);
        
        return head;
    }

    // Generate JSON Response Section
    private JSONObject responseSection(String[] arr) throws JSONException {
        JSONObject response = new JSONObject();

        response.put("numTotalResults", 1); // -- Result = 1 Array -- (?)
        response.put("resultType", "us.monoid.json.JSONArray");
        
        JSONArray mJSONArray = new JSONArray(Arrays.asList(arr));        
        response.put("result", mJSONArray);
        
        return response;
    }
}
