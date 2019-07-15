package org.apache.hadoop.security;

import com.cgws.sdp.rpc.portal.UserDoc;
import com.cgws.sdp.auth.plugin.SdpAuthException;
import com.cgws.sdp.auth.plugin.SdpAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.io.UnsupportedEncodingException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Map;

public class SaslSdpServer implements SaslServer {
    public static final Log LOG = LogFactory.getLog(SaslSdpServer.class);

    public static final String SDP_MECHANISM = "SDP_PLAIN" ;
    public static final String SASL_SDP_AUTH_SEPARATOR = " ";

    boolean isComplete = false;
    String authzId;

    @Override
    public String getMechanismName() {
        return SDP_MECHANISM;
    }

    /**
     *
     * @param response
     * @return
     * @throws SaslException
     */
    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
        /*
         * Message format (from https://tools.ietf.org/html/rfc4616):
         *
         * message   = [authzid] UTF8NUL authcid UTF8NUL passwd
         * authcid   = 1*SAFE ; MUST accept up to 255 octets
         * authzid   = 1*SAFE ; MUST accept up to 255 octets
         * passwd    = 1*SAFE ; MUST accept up to 255 octets
         * UTF8NUL   = %x00 ; UTF-8 encoded NUL character
         *
         * SAFE      = UTF1 / UTF2 / UTF3 / UTF4
         *                ;; any UTF-8 encoded Unicode character except NUL
         */

        String[] tokens;
        try {
            LOG.info("Start to authenticate user with sdp mechanism. input info:"+ new String(response, "UTF-8"));

            tokens = new String(response, "UTF-8").split("\u0000");
        } catch (UnsupportedEncodingException e) {
            throw new SaslException("UTF-8 encoding not supported", e);
        }
        if (tokens.length != 3)
            throw new SaslException("Invalid SASL/SDP response: expected 3 tokens, got " + tokens.length);

        String authcInfo = tokens[1];

        String[] authInfoparts = authcInfo.split(SaslSdpServer.SASL_SDP_AUTH_SEPARATOR);

        if (authcInfo.isEmpty() || ( authInfoparts.length != 4 ) ) {
            LOG.error("Authentication failed with sdp mechanism: sdp authentication params does not specified");
            throw new SaslException("Authentication failed with sdp mechanism: sdp authentication params does not specified");
        }
        try {
            UserDoc userDoc = SdpAuthenticator.getInstance().authenticate(authInfoparts[0], Long.parseLong(authInfoparts[1]), Integer.parseInt(authInfoparts[2]), authInfoparts[3]);
            authzId = userDoc.getName();
        } catch (SdpAuthException e) {
            LOG.warn( "Authentication failed with sdp mechanism: client params received:" + authcInfo );
            throw new SaslException(e.getMessage());
        }
        LOG.info("Authentication successfully with sdp mechanism：user " + authzId );

        isComplete = true;
        return new byte[0];
    }

    @Override
    public boolean isComplete() {
        return isComplete;
    }

    @Override
    public String getAuthorizationID() {
        if( !isComplete ){
            throw new IllegalStateException(" SDP SASL Authentication exchange has not completed");
        }
        return authzId;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
        if (!isComplete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return Arrays.copyOfRange(incoming, offset, offset + len);
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
        if (!isComplete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return Arrays.copyOfRange(outgoing, offset, offset + len);
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        if (!isComplete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return null;
    }

    @Override
    public void dispose() throws SaslException {

    }


    //sasl factory class
    public static class SdpSaslServerFactory implements SaslServerFactory {

        @Override
        public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
            if( SDP_MECHANISM.equalsIgnoreCase( mechanism ) ){
                return new SaslSdpServer();
            }else{
                throw new SaslException( "Unsupported mechanism, only SDP suported!" );
            }
        }

        @Override
        public String[] getMechanismNames(Map<String, ?> props) {
            return new String[]{SDP_MECHANISM};
        }
    }


    //sasl provider class
    public static  class SdpSaslServerProvider extends Provider {

        public SdpSaslServerProvider() {

            super( "SASL/SDP authentication  server provider" , 1.0 , "sdp sasl server provider");
            super.put("SaslServerFactory." + SDP_MECHANISM, SdpSaslServerFactory.class.getName());
        }

        public static void initialize() {
            Security.addProvider(new SdpSaslServerProvider());
        }
    }
}