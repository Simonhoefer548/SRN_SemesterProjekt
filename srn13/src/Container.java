import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.json.JSONObject;

//SchlÃ¼sselbund
public class Container {

	private JSONObject fullJSON;
	private JSONObject privJSON;
	private JSONObject pubJSON;
	private String owner;
	Container(String containername,String own) throws IOException{
		this.createContainer(containername);	
		this.owner=own;
	}

	private void createContainer(String container) throws IOException {
		
		this.fullJSON = new JSONObject();
		this.privJSON = new JSONObject();
		this.pubJSON = new JSONObject();
		
		//Ã¶ffentliche Infos
		JSONObject ju = new JSONObject();
		ju.put("containername", container);
		//Fileliste
		//ju.put("containername", container);
		//TODO Erzeugung von Ã¶ffentlichen /Private Keysd
		//	ju.put("pubkey", null);
		
		//geheime Infos
		JSONObject js = new JSONObject();
		//js.put("privkey",privkey)
		//js.put("sharedKey",privkey)
		//js.put("files",null)
		//js.put("integritylist",null)
		//js.put("fileKeyMappingList",null)
		privJSON=js;
		pubJSON=ju;
		this.fullJSON.put("open", ju);
		this.fullJSON.put("secret", js);
		
		saveContainer(container);
		
	}
	public Container getContainer() {
		
		return this;
	}
	
	private void saveContainer(String containername) throws IOException {
	
		FileWriter fw = new FileWriter(containername);
		//TODO PasswortverschlÃ¼sselung des privJSON -> done!
		
		
		//TODO für jedes PW ein eigenes Salt
		
		String settingFile = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
        JSONObject settingJSON = new JSONObject(settingFile);
        String salt = settingJSON.get("appsalt").toString(); 
		
		//String saltString="testSalttoString";
		byte[] saltAsByteArray=salt.getBytes();
		// ToString des privaten Json Objektes mittels SHA512 und noch FEST definierten Salt verschlüsselt
		String zuVerschlüsselenMitSha512=SHA512.encryptString(this.privJSON.toString(), saltAsByteArray);
		System.out.println(zuVerschlüsselenMitSha512);
		
		
		
		JSONObject export = new JSONObject();
		export.put("open", this.pubJSON);
		export.put("secret", this.privJSON);
		fw.write(export.toString());
		fw.close();
		System.out.println("Verändert");
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
	
	
	
}
