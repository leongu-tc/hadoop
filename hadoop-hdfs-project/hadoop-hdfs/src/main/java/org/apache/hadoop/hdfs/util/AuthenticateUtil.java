package org.apache.hadoop.hdfs.util;

import java.io.IOException;

import com.cgws.sdp.auth.common.SdpAuthInfo;
import com.cgws.sdp.auth.common.SdpAuthUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;

public class AuthenticateUtil {
	
	private final static Log LOG = LogFactory.getLog(
			AuthenticateUtil.class);

	public static AuthenticateEntity getAuthenticateEntity(Configuration conf) throws IOException{
		String publicKey = conf.get("hadoop_security_authentication_sdp_publickey");
        String privateKey = conf.get("hadoop_security_authentication_sdp_privatekey");
        String userName = conf.get("hadoop_security_authentication_sdp_username");
        if( publicKey == null ){
          publicKey = conf.get("hadoop.security.authentication.sdp.publickey");
        }
        if( privateKey == null ){
          privateKey = conf.get("hadoop.security.authentication.sdp.privatekey");
        }
        if(userName == null){
          userName = conf.get("hadoop.security.authentication.sdp.username");
        }
        if( publicKey == null || privateKey == null ){
            LOG.error("Authenticate with sdp sasl mechanism. No publicKey or privateKey set.[publicKey:"+publicKey+"]");
            throw new IOException("Authenticate with sdp sasl mechanism. No publicKey or privateKey set[publicKey:"+ publicKey +"]");
        }

		SdpAuthInfo sdpAuthInfo = SdpAuthUtil.generateSdpAuthInfo(publicKey,privateKey);
        return new AuthenticateEntity(publicKey, privateKey, userName, sdpAuthInfo.getSignature(), sdpAuthInfo.getTimestamp(), sdpAuthInfo.getRandomValue());
	}
	
	public static class AuthenticateEntity{
		private String publicKey;
		private String privateKey;
		private String userName;
		private String signature;
		
		private long timestamp;
		private int randomValue;
		
		public AuthenticateEntity(String publicKey, String privateKey, String userName, String signature, long timestamp, int randomValue) {
			this.publicKey = publicKey;
			this.privateKey = privateKey;
			this.userName = userName;
			this.signature = signature;
			this.timestamp = timestamp;
			this.randomValue = randomValue;
		}
		public String getPublicKey() {
			return publicKey;
		}
		public void setPublicKey(String publicKey) {
			this.publicKey = publicKey;
		}
		public String getPrivateKey() {
			return privateKey;
		}
		public void setPrivateKey(String privateKey) {
			this.privateKey = privateKey;
		}
		public String getUserName() {
			return userName;
		}
		public void setUserName(String userName) {
			this.userName = userName;
		}
		public String getSignature() {
			return signature;
		}
		public void setSignature(String signature) {
			this.signature = signature;
		}
		
		public String getHttpHeaderKey(){
			return "sdp-auth";
		}
		public String getHttpHeaderAuthValue(){
			return this.publicKey + " " + this.timestamp + " " + this.randomValue + " " + this.signature;
		}

		@Override
		public String toString() {
			return "AuthenticateEntity{" +
					"publicKey='" + publicKey + '\'' +
					", userName='" + userName + '\'' +
					", signature='" + signature + '\'' +
					", timestamp=" + timestamp +
					", randomValue=" + randomValue +
					'}';
		}
	}
}


