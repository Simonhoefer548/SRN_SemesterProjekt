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

	public void addFileKey(SecretKey symKey, String filename) throws IOException {
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
		Scanner in = new Scanner(System.in);
		// System.out.println("Bitte Passwort eingeben");

		// TODO Hier w�rde das bereits existiernde Passwort �berschrieben werden!
		String pw = AES_Encryption.validatePassword();
		// in.nextLine();

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
		//"test1:SH-key1-test1:luca\""
		for (int i = 0; i < keyarray.length(); i++) {
			JSONObject obj = (JSONObject) keyarray.get(i);
			System.out.println(obj);
			String test2 = obj.get("keyName").toString().split(":")[1];
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

	public void deletekeys(String filename) throws IOException {
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
//		Scanner in = new Scanner(System.in);
//		System.out.println("Bitte Passwort eingeben");

		// TODO auch hier kann das existiernde Passwort �berschrieben werden!
		String pw = AES_Encryption.validatePassword();
		// in.nextLine();
		this.saveContainer(this.name, pw);

	}

	public void addBulk(JSONObject bulkObj, JSONObject containerJSON) throws IOException {
		JSONObject pubFromContainer = containerJSON;
		JSONObject open = (JSONObject) pubFromContainer.get("open");
		String bulktoSave = open.get("bulk").toString();
		JSONArray bulkja = new JSONArray(bulktoSave);
		bulkja.put(bulkObj);
		open.remove("bulk");
		open.put("bulk", bulkja);
		JSONObject jo = open;
		pubFromContainer.remove("open");
		pubFromContainer.put("open", jo);
		System.out.println("Password");
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

		String settingFile = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
		JSONObject settingJSON = new JSONObject(settingFile);

		// TODO PW muss noch hier andocken
		// TODO Passwort Datei �berpr�fen
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

}
