import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

//Schlüsselbund
public class Container {

	private JSONObject fullJSON;
	private JSONObject privJSON;
	private JSONObject pubJSON;
	private String owner;
	
	Container(String containername,String own,String password) throws IOException{
		this.createContainer(containername,password);	
		this.owner=own;
	}

	public Container(JSONObject secret,JSONObject pub, String user) {
		this.fullJSON = new JSONObject();
		fullJSON.put("open", pub);
		fullJSON.put("secret", secret);
		this.privJSON=secret;
		this.pubJSON=pub;
		this.owner=user;
		
	}
	private void createContainer(String container,String password) throws IOException {
		
		this.fullJSON = new JSONObject();
		this.privJSON = new JSONObject();
		this.pubJSON = new JSONObject();
		
		//öffentliche Infos
		JSONObject ju = new JSONObject();
		ju.put("containername", container);
		//Fileliste
		//ju.put("containername", container);
		//TODO Erzeugung von öffentlichen /Private Keysd
		//	ju.put("pubkey", null);
		
		//geheime Infos
		JSONObject js = new JSONObject();
		//TODO User spezifische Public & Private Keys in Json speichern
		KeyPair publicAndPrivateKey=RSA_Encryption.KeyGenerator();
		
		
		
		
		
		ju.put("publickey",Base64.getEncoder().encodeToString(publicAndPrivateKey.getPublic().getEncoded()));
		js.put("privatekey",Base64.getEncoder().encodeToString(publicAndPrivateKey.getPrivate().getEncoded()));
		
		//js.put("privkey",privkey)
		//js.put("sharedKey",privkey)
		//js.put("files",null)
		//js.put("integritylist",null)
		//js.put("fileKeyMappingList",null)
		privJSON=js;
		pubJSON=ju;
		this.fullJSON.put("open", ju);
		this.fullJSON.put("secret", js);
		
		saveContainer(container,password);
		
	}
	public Container getContainer() {
		
		return this;
	}
	
	private void saveContainer(String containername,String password) throws IOException {
	
		FileWriter fw = new FileWriter(containername);
		//TODO Passwortverschlüsselung des privJSON -> done!
		
		
		
		
		String settingFile = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
        JSONObject settingJSON = new JSONObject(settingFile);
        
        //TODO PW muss noch hier andocken
        String keyGeneretedWithPassword=password;
        SecretKey aesKey = new SecretKeySpec(keyGeneretedWithPassword.getBytes(), "AES");
        String jsonPrivate="";
        try {
			jsonPrivate=AES_Encryption.encrypt(this.privJSON.toString(), aesKey);
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
			System.err.print(e.getMessage());
			e.printStackTrace();
		}
        
		
		
		
		JSONObject export = new JSONObject();
		export.put("open", this.pubJSON);
		export.put("secret", jsonPrivate);
		fw.write(export.toString());
		fw.close();
		System.out.println("Verschlsselt");
/*
 * 
		encrypted_private = crypto.encrypt_bytes(self.aes_key, private_contents.encode(), public_contents.encode())


 */
	}

	public JSONObject getFullJSON() {
		return fullJSON;
	}

	public JSONObject getPrivJSON() {
		return privJSON;
	}

	public JSONObject getPubJSON() {
		return pubJSON;
	}

	public String getOwner() {
		return owner;
	}
	
	public Container setContainer() {
		return null;
	}
	
	
	
}
