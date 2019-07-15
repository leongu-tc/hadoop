package org.apache.hadoop.security.authentication.server;

import com.cgws.sdp.auth.plugin.SdpAuthenticator;
import com.cgws.sdp.rpc.portal.UserDoc;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SdpAuthenticationHandler implements AuthenticationHandler {

    private static Logger LOG = LoggerFactory.getLogger(SdpAuthenticationHandler.class);

    public static final String TYPE = "sdp";

    public static final String SDP_PUBLIC_KEY = "publicKey";
    public static final String SDP_PRIVATE_KEY = "privateKey";
    public static final String SDP_TIMESTAMP = "timestamp";
    public static final String SDP_NONCE = "randomValue";
    public static final String SDP_SIG = "nonce";

    private static final String SDP_AUTH = "sdp-auth";

    public static final String HTTP_HEADER_AUTH = "sdp-auth";
    private static final String AUTH_HEADER_CONTENT_DELIMITER = " ";
    public static final String SDP_AUTHENTICATED_USER_NAME = "sdp.authonticated.user";

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public void init(Properties config) throws ServletException {
    }

    @Override
    public void destroy() {

    }

    @Override
    public boolean managementOperation(AuthenticationToken token, HttpServletRequest request, HttpServletResponse response) throws IOException, AuthenticationException {
        return true;
    }

    @Override
    public AuthenticationToken authenticate(HttpServletRequest request, HttpServletResponse response) throws IOException, AuthenticationException {

        String publicKey = null;
        String privateKey = null;
        String timestamp = null;
        String randomValue = null;
        String signature = null;
        AuthenticationToken token = null;

        String authContent = request.getHeader(HTTP_HEADER_AUTH);
        if (authContent != null ) {
            String[] authSplits = authContent.split( AUTH_HEADER_CONTENT_DELIMITER );
            if( authSplits.length == 4  ){
                publicKey = authSplits[0];
                timestamp  = authSplits[1];
                randomValue = authSplits[2];
                signature = authSplits[3];

            }else if( authSplits.length == 2 ){
                publicKey = authSplits[0];
                privateKey = authSplits[1];
            }
            try {
                if( signature != null ) {

                    UserDoc userDoc = SdpAuthenticator.getInstance().authenticate(publicKey, Long.parseLong(timestamp), Integer.parseInt(randomValue), signature);
                    token = new AuthenticationToken(userDoc.getName(), userDoc.getName(), getType());
                }else{
                    LOG.error("Sdp authentication info is invalid:{}", authContent);
                    throw new AuthenticationException("Sdp authentication info is invalid");
                }
            }catch (Exception e){
                LOG.warn("Sdp authentication failed, auth info:" + authContent, e);
                throw new AuthenticationException("Sdp authentication failed.",e);
            }
        }
        if( token == null ){
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setHeader(WWW_AUTHENTICATE, SDP_AUTH);
        }else{
            request.setAttribute(SDP_AUTHENTICATED_USER_NAME,token.getUserName());
        }
        return token;
    }
}
