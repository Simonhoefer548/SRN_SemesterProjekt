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
	private static int CONTAINERCOUNT = 0;

	Container(String containername, String own, String password)
			throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
			NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
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

	private void createContainer(String container, String password)
			throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
			NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		this.fullJSON = new JSONObject();
		this.privJSON = new JSONObject();
		this.pubJSON = new JSONObject();

		// öffentliche Infos
		JSONObject ju = new JSONObject();
		ju.put("containername", container);
		ju.put("bulk", "[]");

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
		js.put("sharekeys", "[]");
		js.put("shareUserList", "[]");
		js.put("integritylist", "[]");
		ju.put("fileKeyMappingList", "[]");
		this.privJSON = js;
		this.pubJSON = ju;
		this.fullJSON.put("open", ju);
		this.fullJSON.put("secret", js);

		saveContainer(container, password);
		Container.CONTAINERCOUNT++;
		if (Container.CONTAINERCOUNT > 1) {
			sendAllUserPubKey(Base64.getEncoder().encodeToString(publicAndPrivateKey.getPublic().getEncoded()));

		}

	}

	private void sendAllUserPubKey(String pubkey)
			throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
			NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		// was brauche ich?
		// pubkey aller User -> für jeden User machst du so
		// pro User nehme sein pubKey verschlüssele mein pubkey und schreiben es in
		// seinem bulk
		// select pubkey
		// nehme mein pubkey
		// schreibe es ins bulk

		String settings = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
		JSONObject userJSON = new JSONObject(settings);
		JSONArray ja = (JSONArray) userJSON.get("users");
		if (ja.length() > 0) {
			for (int i = 0; i < ja.length(); i++) {
				System.out.println();
				// [{"luca":"luca2021_11_24_9f26b74a9cf5682da25a8dee48dffaaa1a8a7e52dd25682b2cd87504c41edb4e2ec0004b6516b2e3a7f1fd349622ba5d4da48b2743b9901827ed0fcf4dd087d7"}
				String user = ja.get(i).toString().split(":")[0].replaceAll("\"", "").replace("{", "");
				String cname = ja.get(i).toString().split(":")[0].replaceAll("\"", "").replace("}", "");

				String container = new String(Files.readAllBytes(Paths.get(cname)), StandardCharsets.UTF_8);
				JSONObject containerJSON = new JSONObject(container);
				JSONObject open = (JSONObject) containerJSON.get("open");

				// pubkey des

				JSONObject bulkObj = new JSONObject();
				bulkObj.put("id", 4);
				bulkObj.put("data", pubkey);
				bulkObj.put("cname", cname);
				bulkObj.put("user", user);
				this.addBulk(bulkObj, containerJSON);

			}
		}

	}

	public Container getContainer() {

		return this;
	}

	public boolean addFileKey(SecretKey symKey, String filename) throws IOException {
		// Passwortabfrage

		String pw = AES_Encryption.validatePassword();
		if (!AES_Encryption.verifyPassword(pw)) {
			return false;
		} else {
			// String in filekeys JSON
			System.out.println(this.fullJSON);
			String keyforjson = Base64.getEncoder().encodeToString(symKey.getEncoded());
			String filekeystosave = this.getPrivJSON().get("filekeys").toString();
			JSONArray ja = new JSONArray(filekeystosave);
			String keyname = "S-key1-" + filename;
			JSONObject tmppriv = this.getPrivJSON();
			JSONObject keyFile = new JSONObject();

			keyFile.put("keyName", keyname);
			keyFile.put("key", keyforjson);

			tmppriv.remove("filekeys");
			ja.put(keyFile);
			tmppriv.put("filekeys", ja);

			this.privJSON = tmppriv;
			// Mapping

			String filekeymapping = this.getPubJSON().get("fileKeyMappingList").toString();
			System.out.println(filekeymapping);
			JSONArray jaMap = new JSONArray(filekeymapping);

			System.out.println(jaMap);
			JSONObject tmppub = this.getPubJSON();
			String autorkeyfile = filename + ":" + keyname + ":" + this.owner;

			jaMap.put(autorkeyfile);
			tmppub.remove("fileKeyMappingList");
			tmppub.put("fileKeyMappingList", jaMap);

			this.pubJSON = tmppub;
			JSONObject pub2 = new JSONObject();
			pub2.put("open", this.getPubJSON());
			pub2.put("secret", this.getPrivJSON());
			this.fullJSON = pub2;
			System.out.println(this.fullJSON);

			this.saveContainer(this.name, pw);
			return true;
		}
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

	public SecretKey getKeyFromName(String filename) {
		String keyname = "";
		String key = "";
		JSONObject secret = (JSONObject) this.fullJSON.get("secret");
		JSONArray ja = (JSONArray) this.getPubJSON().get("fileKeyMappingList");
		// ja = new JSONArray(fileKeymap);

		for (int i = 0; i < ja.length(); i++) {
			String sel = ja.get(i).toString();
			String[] array = sel.split(":");
			String fileName = array[0];

			if (filename.equals(fileName)) {
				// richtiges File
				keyname = array[1];
				String creator = array[2];
				break;
			}
		}
		// hole key mithilfe keyname aus secret
		String filekeys = secret.get("filekeys").toString();
		JSONArray keyarray = new JSONArray(filekeys);

		String shareKeysString = secret.get("sharekeys").toString();
		JSONArray share = new JSONArray(shareKeysString);
		for (int i = 0; i < share.length(); i++) {
			keyarray.put(share.get(i));
		}
		// "test1:SH-key1-test1:luca\""
		for (int i = 0; i < keyarray.length(); i++) {
			JSONObject obj = (JSONObject) keyarray.get(i);
			System.out.println(obj);
			String test2 = obj.get("keyName").toString();

			if (test2.equals(keyname)) {
				key = obj.getString("key");
			}
		}
		// String keyforjson = Base64.getEncoder().encodeToString(symKey.getEncoded());
		byte[] decodedKey = Base64.getDecoder().decode(key);
		// rebuild key using SecretKeySpec
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		return originalKey;

	}

	public boolean deletekeys(String filename) throws IOException {
		// Passwortabfrage
		// Passwort von Nutzer einlesen
		String pw = AES_Encryption.validatePassword();
		if (!AES_Encryption.verifyPassword(pw)) {
			return false;
		}

		// filekeymap
		JSONObject tmp = this.getPubJSON();
		JSONArray ja = (JSONArray) this.getPubJSON().get("fileKeyMappingList");
		JSONArray newJA = new JSONArray();
		String keyName = "";

		for (int i = 0; i < ja.length(); i++) {
			String filekeymap = ja.get(i).toString();
			String actFilename = filekeymap.split(":")[0];
			if (actFilename.equals(filename)) {
				keyName = filekeymap.split(":")[1];

			} else {
				newJA.put(filekeymap);
			}

		}
		System.out.println(this.getPubJSON());

		this.getPubJSON().remove("fileKeyMappingList");
		System.out.println(this.getPubJSON());
		this.getPubJSON().put("fileKeyMappingList", newJA);
		System.out.println(this.getPubJSON());

		// key aus fileskeys

		String filekeystosave = this.getPrivJSON().get("filekeys").toString();
		JSONArray fka = new JSONArray(filekeystosave);
		// alle fileskeys sind in fka
		JSONArray newJAfka = new JSONArray();

		for (int i = 0; i < fka.length(); i++) {
			// befülle newJAfka mit werten außer das zu löschende
			JSONObject keyFile = (JSONObject) fka.get(i);
			String keyname = keyFile.get("keyName").toString();
			if (keyname.equals(keyName)) {

			} else {
				newJAfka.put(keyFile);
			}

		}
		System.out.println(this.getPrivJSON());
		this.getPrivJSON().remove("filekeys");
		System.out.println(this.getPrivJSON());

		this.getPrivJSON().put("filekeys", newJAfka);
		System.out.println(this.getPrivJSON());

		JSONObject pub2 = new JSONObject();
		pub2.put("open", this.getPubJSON());
		pub2.put("secret", this.getPrivJSON());
		System.out.println(this.getPrivJSON());
		this.fullJSON = pub2;

		this.saveContainer(this.name, pw);
		return true;
	}

	public void addBulk(JSONObject bulkObj, JSONObject containerJSON)
			throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
			NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		// [{1,2},{1,2},{1,2},{1,2}]
		// hole complette JSOn /Cotainer
		JSONObject pubFromContainer = containerJSON;
		// hole open Bereich JSON
		JSONObject open = (JSONObject) pubFromContainer.get("open");
		// gib ganzen JSON aus
		String bulktoSave = open.get("bulk").toString();
		// mach JSON zu JSONARRay []
		JSONArray jaWithOtherBulks = new JSONArray(bulktoSave);
		String pubkeyFromOther = open.get("publickey").toString();

		// create sym key
		SecretKey symKey = AES_Encryption.generateKey(256);

		// Sym as String
		String symKeyString = Base64.getEncoder().encodeToString(symKey.getEncoded());

		String decrybulk = AES_Encryption.encrypt(bulkObj.toString(), symKey);

		byte[] encrSymKey = RSA_Encryption.encryptString(symKeyString, pubkeyFromOther);

		// Verschlüssele vollstädigen bulk mit sym key
		JSONObject fullBulkobj = new JSONObject();
		fullBulkobj.put("encsymkey", Base64.getEncoder().encodeToString(encrSymKey));
		fullBulkobj.put("encr", decrybulk);

		jaWithOtherBulks.put(fullBulkobj);
		open.remove("bulk");
		open.put("bulk", jaWithOtherBulks);
		JSONObject jo = open;
		pubFromContainer.remove("open");
		pubFromContainer.put("open", jo);
		this.saveContainerByOthers(open.get("containername").toString(), pubFromContainer);

	}

	private void saveContainerByOthers(String containername, JSONObject container) throws IOException {
		System.out.println(container);
		System.out.println(containername);
		FileWriter fw = new FileWriter(containername);
		fw.write(container.toString());
		fw.close();
		System.out.println("Gespeichert");

	}

	private void saveContainer(String containername, String password) throws IOException {

		// wennFile vorhanden

		FileWriter fw = new FileWriter(containername);

		// String settingFile = new
		// String(Files.readAllBytes(Paths.get("settings.json")),
		// StandardCharsets.UTF_8);
		// JSONObject settingJSON = new JSONObject(settingFile);

		// TODO PW muss noch hier andocken
		// TODO Passwort Datei �berpr�fen
		SecretKey aesKey = new SecretKeySpec(password.getBytes(), "AES");
		String jsonPrivate = "";
		try {
			jsonPrivate = AES_Encryption.encrypt(this.privJSON.toString(), aesKey);
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
			System.err.print(e.getMessage());
			e.printStackTrace();
		}

		System.out.println(this.pubJSON);

		JSONObject newObj = new JSONObject();
		newObj.put("open", this.pubJSON);
		System.out.println(newObj.toString());
		newObj.put("secret", jsonPrivate);
		System.out.println(newObj.toString());
		fw.write(newObj.toString());
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

	public void addShareKey(JSONObject oldPrivJSON, JSONObject oldPubJSON) throws IOException {
		System.out.println(oldPrivJSON);
		System.out.println(oldPubJSON);

		this.privJSON = oldPrivJSON;
		this.pubJSON = oldPubJSON;
		JSONObject pub2 = new JSONObject();
		pub2.put("open", this.getPubJSON());
		pub2.put("secret", this.getPrivJSON());
		System.out.println(this.getPrivJSON());
		this.fullJSON = pub2;

		saveContainer(this.name, AES_Encryption.validatePassword());

	}

	public void resetBulk() throws IOException {
		String pw = AES_Encryption.validatePassword();
		this.saveContainer(name, pw);

	}

	public void addShareUserList(JSONArray jatmp) throws IOException {
		JSONObject tmp = this.getPrivJSON();
		tmp.remove("shareUserList");
		tmp.put("shareUserList", jatmp);
		this.privJSON = tmp;
		JSONObject pub2 = new JSONObject();
		pub2.put("open", this.getPubJSON());
		pub2.put("secret", this.getPrivJSON());
		System.out.println(this.getPrivJSON());
		this.fullJSON = pub2;
		this.saveContainer(this.name, AES_Encryption.validatePassword());
	}

	public void removeShare(JSONArray newArray, JSONArray newMapArray) throws IOException {
		this.pubJSON.remove("fileKeyMappingList");
		this.privJSON.remove("sharekeys");

		this.pubJSON.put("fileKeyMappingList", newArray);
		this.pubJSON.put("sharekeys", newMapArray);
		JSONObject pub2 = new JSONObject();
		pub2.put("open", this.getPubJSON());
		pub2.put("secret", this.getPrivJSON());
		this.fullJSON = pub2;
		this.saveContainer(this.name, AES_Encryption.validatePassword());

	}

	public void addDeletedBulkForAll(String filename)
			throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
			NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		String shareUserList = this.getPrivJSON().get("shareUserList").toString();
		// [{"file":"test1","cname":"bera2021_11_24_4c307a812539d794d8178fa00f8c2133878f31a6db862fba21f5d385ed66bd36fcbea42055b4678fed344e2359135d6f4385eb69b5f490747e0a4b5c9860379d","user":"bera"},{"file":"test1","cname":"sandra2021_11_24_3fa2ec7d18891e93cd1ac5af528f129e9d5a0752213ea30aaafcb36d8bbc6ef7cba88077dfc7de9428d225733a891a465ca4b792d8200126b21fd11c76d6294c","user":"sandra"}]
		JSONArray jatmp = new JSONArray(shareUserList);
		for (int i = 0; i < jatmp.length(); i++) {
			JSONObject jo = jatmp.getJSONObject(i);
			if (filename.equals(jo.get("file").toString())) {
				String container = new String(Files.readAllBytes(Paths.get(jo.get("cname").toString())),
						StandardCharsets.UTF_8);
				JSONObject containerJSON = new JSONObject(container);
				JSONObject bulkObj = new JSONObject();
				bulkObj.put("id", 3);
				bulkObj.put("data", filename);
				bulkObj.put("cname", jo.get("cname"));
				this.addBulk(bulkObj, containerJSON);

			}

		}

	}

	public void addInteger(JSONArray jainteglist) throws IOException {
		this.getPrivJSON().remove("integritylist");
		this.getPrivJSON().put("integritylist", jainteglist);
		JSONObject pub2 = new JSONObject();
		pub2.put("open", this.getPubJSON());
		pub2.put("secret", this.getPrivJSON());
		System.out.println(this.getPrivJSON());
		this.fullJSON = pub2;
		this.saveContainer(this.name, AES_Encryption.validatePassword());
	}

}
