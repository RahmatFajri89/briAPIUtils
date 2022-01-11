package BriAPIUtils.utils;

// -----( IS Java Code Template v1.2

import com.wm.data.*;
import com.wm.util.Values;
import com.wm.app.b2b.server.Service;
import com.wm.app.b2b.server.ServiceException;
// --- <<IS-START-IMPORTS>> ---
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
// --- <<IS-END-IMPORTS>> ---

public final class java

{
	// ---( internal utility methods )---

	final static java _instance = new java();

	static java _newInstance() { return new java(); }

	static java _cast(Object o) { return (java)o; }

	// ---( server methods )---




	public static final void verifyBriSignature (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(verifyBriSignature)>> ---
		// @sigtype java 3.5
		// [i] field:0:required path
		// [i] field:0:required verb
		// [i] field:0:required token
		// [i] field:0:required timestamp
		// [i] field:0:required body
		// [i] field:0:required key
		// [i] field:0:required signatureRequest
		// pipeline
		String JAVA_SERVICE = "[verifyBriSignature] ";
		IDataCursor pipelineCursor = pipeline.getCursor();
		String	path = IDataUtil.getString( pipelineCursor, "path" );
		String	verb = IDataUtil.getString( pipelineCursor, "verb" );
		String	token = IDataUtil.getString( pipelineCursor, "token" );
		String	timestamp = IDataUtil.getString( pipelineCursor, "timestamp" );
		String	body = IDataUtil.getString( pipelineCursor, "body" );
		String	key = IDataUtil.getString( pipelineCursor, "key" );
		String	signatureRequest = IDataUtil.getString( pipelineCursor, "signatureRequest" );
		pipelineCursor.destroy();
		
		body = body == null || body.isEmpty() ? "" : body; 
		if(!body.isEmpty()){
			ObjectMapper objectMapper = new ObjectMapper();
		    try {
				JsonNode jsonNode = objectMapper.readValue(body, JsonNode.class);
				body = jsonNode.toString();
			} catch (Exception e) {
				e.printStackTrace();
				logMessageToServerLog(pipeline, JAVA_SERVICE + "Exception = " + e.getMessage(), null, "error");
				body = "";
			} 
		}
		
		String payload = "path="+path+"&verb="+verb+"&token="+token+"&timestamp="+timestamp+"&body="+body;
		
		byte[] hmacSha256 = null;
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
			mac.init(secretKeySpec);
			hmacSha256 = mac.doFinal(payload.getBytes());
		} catch (Exception e) {
			throw new ServiceException("Failed to calculate signature");
		}
		
		String signature = Base64.getEncoder().encodeToString(hmacSha256);
		
		if (signatureRequest == null) throw new ServiceException("Signature is not provided");
		
		if (! signatureRequest.equals(signature)) throw new ServiceException("Signature is not valid");
		// --- <<IS-END>> ---

                
	}

	// --- <<IS-START-SHARED>> ---
	public static void logMessageToServerLog(
			IData pipeline, 
		    String message) throws ServiceException{
		logMessageToServerLog(pipeline,"[BriAPIUtils]"+message,null,null);
	}
	
	public static void logMessageToServerLog(
		    IData pipeline, 
		    String message, 
		    String function, 
		    String level) 
		    throws ServiceException 
		{ 
		    IDataCursor inputCursor = pipeline.getCursor(); 
		    IDataUtil.put(inputCursor, "message", message); 
		    IDataUtil.put(inputCursor, "function", function); 
		    IDataUtil.put(inputCursor, "level", level); 
		    inputCursor.destroy(); 
	
		    try
		    {
		        Service.doInvoke("pub.flow", "debugLog", pipeline);
		    }
		    catch (Exception e)
		    {
		        throw new ServiceException(e.getMessage());
		    }
		}
	// --- <<IS-END-SHARED>> ---
}

