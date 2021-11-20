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
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONObject;

//Schlüsselbund
public class Container {

	private JSONObject fullJSON;
	private JSONObject privJSON;
	private JSONObject pubJSON;
	private String owner;
	private String name;

	Container(String containername, String own, String password) throws IOException {
		this.createContainer(containername, password);
		this.owner = own;
		this.name = containername;
	}

	public Container(JSONObject secret, JSONObject pub, String user) {
		this.fullJSON = new JSONObject();
		fullJSON.put("open", pub);
		fullJSON.put("secret", secret);
		this.privJSON = secret;
		this.pubJSON = pub;
		this.owner = user;
		this.name = pubJSON.getString("containername");
	}

	private void createContainer(String container, String password) throws IOException {

		this.fullJSON = new JSONObject();
		this.privJSON = new JSONObject();
		this.pubJSON = new JSONObject();

		// öffentliche Infos
		JSONObject ju = new JSONObject();
		ju.put("containername", container);
		// Fileliste
		// ju.put("containername", container);
		// TODO Erzeugung von öffentlichen /Private Keysd
		// ju.put("pubkey", null);

		// geheime Infos
		JSONObject js = new JSONObject();
		// TODO User spezifische Public & Private Keys in Json speichern
		KeyPair publicAndPrivateKey = RSA_Encryption.KeyGenerator();

		ju.put("publickey", Base64.getEncoder().encodeToString(publicAndPrivateKey.getPublic().getEncoded()));
		js.put("privatekey", Base64.getEncoder().encodeToString(publicAndPrivateKey.getPrivate().getEncoded()));

		// Shared Keys sind Keys welche man von anderen Nutzern erhalten hat
		// js.put("sharedKey",privkey)

		// Filekeys sind eigen erstelle symmetrische Keys zum entschl�ssen einer Datei
		js.put("filekeys", "[]");

		// js.put("integritylist",null)
		ju.put("fileKeyMappingList", "[]");
		this.privJSON = js;
		this.pubJSON = ju;
		this.fullJSON.put("open", ju);
		this.fullJSON.put("secret", js);

		saveContainer(container, password);

	}

	public Container getContainer() {

		return this;
	}

	private void saveContainer(String containername, String password) throws IOException {

		FileWriter fw = new FileWriter(containername);
		// TODO Passwortverschlüsselung des privJSON -> done!

		String settingFile = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
		JSONObject settingJSON = new JSONObject(settingFile);

		// TODO PW muss noch hier andocken
		String keyGeneretedWithPassword = password;
		SecretKey aesKey = new SecretKeySpec(keyGeneretedWithPassword.getBytes(), "AES");
		String jsonPrivate = "";
		try {
			jsonPrivate = AES_Encryption.encrypt(this.privJSON.toString(), aesKey);
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
		System.out.println("Verschluesselt");
		/*
		 * 
		 * encrypted_private = crypto.encrypt_bytes(self.aes_key,
		 * private_contents.encode(), public_contents.encode())
		 * 
		 * 
		 */
	}

	public void addFileKey(SecretKey symKey, String filename) throws IOException {
		// String in filekeys JSON
		System.out.println(this.fullJSON);
		String keyforjson = Base64.getEncoder().encodeToString(symKey.getEncoded());
		String filekeystosave = this.getPrivJSON().get("filekeys").toString();
		JSONArray ja = new JSONArray(filekeystosave);
		String keyname = "key1:" + filename;
		JSONObject tmppriv = this.getPrivJSON();
		JSONObject keyFile = new JSONObject();

		keyFile.put("keyName", keyname);
		keyFile.put("key", keyforjson);

		tmppriv.remove("filekeys");
		ja.put(keyFile);
		tmppriv.put("filekeys", ja);


		this.privJSON = tmppriv;
		//Mapping
		
		String filekeymapping = this.getPubJSON().get("fileKeyMappingList").toString();
		System.out.println(filekeymapping);
		JSONArray jaMap = new JSONArray(filekeymapping);

		System.out.println(jaMap);
		JSONObject tmppub = this.getPubJSON();
		String autorkeyfile = filename + ":" + keyname + ":as" + this.owner;

		jaMap.put(autorkeyfile);
		tmppub.remove("fileKeyMappingList");
		tmppub.put("fileKeyMappingList", jaMap);

		this.pubJSON = tmppub;
		JSONObject pub2 = new JSONObject();
		pub2.put("open", this.getPubJSON());
		pub2.put("secret", this.getPrivJSON());
		this.fullJSON = pub2;
		System.out.println(this.fullJSON);
		Scanner in = new Scanner(System.in);
		System.out.println("Bitte Passwort eingeben");
		String pw = in.nextLine();
		this.saveContainer(this.name, pw);

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
