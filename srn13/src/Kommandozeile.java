import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class Kommandozeile {

	public static void main(String[] args)
			throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		System.out.println("Options");

		Scanner sc = new Scanner(System.in);
		Container selected = null;
		String number = "";

		while (!number.equals("1") && !number.equals("2")) {
			System.out.println("1: Create User / 2: Login ");
			number = sc.nextLine();
			if (!number.equals("1") && !number.equals("2")) {
				System.out.println("Incorrect Input!" + "\n" + "Please select a valid Option");
			}
		}

		if (number.equals("1")) {
			selected = createUser();
		} else if (number.equals("2")) {
			selected = login();
		}
		// Nun haben wir einen Container selektiert

		boolean weiter = true;

		if (selected != null) {
			verarbeiteBulk(selected);
		}

		while (weiter && selected != null) {

			System.out.println("Options");
			System.out.println("1.Add File / 2. Open File / 3.Delete File / 4. File Share  / 5.Remove Share / 6. Exit");
			number = sc.nextLine();
			switch (number) {
			case "1": {
				// File verschluesseln
				addFile(selected);

				break;
			}
			case "2": {
				openFile(selected);
				break;

			}
			case "3": {
				deleteFile(selected);
				// nur wenn der ersteller
				break;
			}
			case "4": {
				fileShare(selected);
				// Nur der ersteller kann File share einer Datei einstellen
				// Hier werden nur Files angezeigt die selber hinzugefuegt wurden
				// Hier koennen wir ein File auswaehlen und dann User File Zugriff geben oder
				// nicht
				break;
			}
			case "5": {
				removeFileShare(selected);

				break;
			}
			case "6": {
				weiter = false;
				selected = null;
				break;
			}
			default:
				System.out.println("Incorrect Input!" + "\n" + "Please select a valid Option");

			}
		}
		sc.close();
		System.out.println("Goodbye");

	}

	/**
	 * Allows the User to revoke File Access for other Users.
	 * @param selected
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static void removeFileShare(Container selected) throws IOException, InvalidKeyException,
	BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		System.out.println("Who you want to revoke Access to File?(Number)");
		String shareUserList = selected.getPrivJSON().get("shareUserList").toString();
		JSONArray jatmp = new JSONArray(shareUserList);
		for (int i = 0; i < jatmp.length(); i++) {
			JSONObject jotmp = jatmp.getJSONObject(i);
			//System.out.println(jotmp);
			System.out.println(i + 1 + "-" + jotmp.get("file") + ":" + jotmp.get("user"));

		}
		// Da hatten wir wieder das Problem wenn String eingegeben wird-> Done
		Scanner sc = new Scanner(System.in);
		int number=1000; 
		try {
			number= Integer.parseInt(sc.nextLine());
		}catch(NumberFormatException e){
			System.out.println("Invalid Input");
			return;
		}
		if (number > jatmp.length()) {
			System.out.println("Invalid Input");
		} else {
			JSONObject tmp = (JSONObject) jatmp.get(number - 1);

			//System.out.println(tmp);
			JSONObject bulkObj = new JSONObject();
			bulkObj.put("id", 2);
			bulkObj.put("data", tmp.get("file"));
			bulkObj.put("fileName", tmp.get("cname"));
			bulkObj.put("sender", selected.getOwner());
			String container = new String(Files.readAllBytes(Paths.get(tmp.get("cname").toString())),
					StandardCharsets.UTF_8);
			JSONObject containerJSON = new JSONObject(container);

			selected.addBulk(bulkObj, containerJSON);

		}
	}

	/**
	 * This Method allows the User to login to his personal Container which will be returned after successful login 
	 * @return 
	 * @throws IOException
	 */
	private static Container login() throws IOException {

		Container c1 = null;
		Scanner sc = new Scanner(System.in);
		String user = "";
		System.out.println("Please enter Username" + "\n" + "('exit' to escape)");

		user = sc.nextLine();
		if (user.equalsIgnoreCase("exit") || user.equals("")) {
			return null;
		}

		String settingFile = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
		JSONObject settingJSON = new JSONObject(settingFile);
		JSONArray ja = new JSONArray(settingJSON.get("users").toString());

		if (!(ja.toString().contains(user))) {
			System.out.println("User does not exist");

		} else {
			String selectedUser = "";
			String containerName = "";
			for (int i = 0; i < ja.length(); i++) {
				selectedUser = ja.getJSONObject(i).toString();
				String newString = selectedUser.replace("{", "").replace("}", "").replaceAll("\"", "");
				String[] splittedSettings = newString.split(":");
				if (user.equals(splittedSettings[0])) {
					selectedUser = splittedSettings[0];
					containerName = splittedSettings[1];
					break;
				}

			}
			String container = new String(Files.readAllBytes(Paths.get(containerName)), StandardCharsets.UTF_8);
			JSONObject containerJSON = new JSONObject(container);
			String secret = containerJSON.get("secret").toString();

			//System.out.println(secret);

			String finalPassword = AES_Encryption.validatePassword();
			// Passwortabfrage
			if (!AES_Encryption.verifyPassword(finalPassword)) {
				return null;
			} else {
				System.out.println("Login successful!");
			}

			SecretKey aesKey = new SecretKeySpec(finalPassword.getBytes(), "AES");

			String jsonString = "";
			try {
				jsonString = AES_Encryption.decrypt(secret, aesKey);
				JSONObject secretJSON = new JSONObject(jsonString);
				JSONObject pubJSON = new JSONObject(containerJSON.get("open").toString());

				c1 = new Container(secretJSON, pubJSON, user);
			} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
					| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {

				// e.printStackTrace();
				System.out.println("Incorrect Password for selected User");
			}

		}

		return c1;
	}

	/**
	 * Checks if User has been granted new Access to Files owned by other Users but also the other way around.
	 * If a Owner revokes Access to his File this Method will update the Permission Status at each Login. 
	 * @param selected
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static void verarbeiteBulk(Container selected) throws InvalidKeyException, NoSuchPaddingException,
	NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {
		// TODO Pr�fen ob Datei schon vorhanden ist

		String test = selected.getPubJSON().get("bulk").toString();
		String privasString = selected.getPrivJSON().get("privatekey").toString();
		//System.out.println(privasString);

		JSONArray ja = new JSONArray();

		JSONArray jatemp = new JSONArray(test);
		for (int i = 0; i < jatemp.length(); i++) {


			//System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++Entschlüsselung");
			JSONObject jotmp = (JSONObject) jatemp.get(i);
			String stringtoDecr = jotmp.get("encr").toString();
			//System.out.println("Verschlüsselter Bulk"+stringtoDecr);
			String encSimKey = jotmp.get("encsymkey").toString();
			//System.out.println("Verschlüsselter Sym Key"+encSimKey);
			String decryptSymKEy = RSA_Encryption.decryptToString(Base64.getDecoder().decode(encSimKey), privasString);
			//System.out.println("Entschlüsstler Sym KEy "+decryptSymKEy);
			byte[] byteString = Base64.getDecoder().decode(stringtoDecr);
			//datasym stringtoDecr
			//decryptsym key 
			byte[] decodedKey = Base64.getDecoder().decode(decryptSymKEy);
			// rebuild key using SecretKeySpec
			SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
			String decData = AES_Encryption.decrypt(stringtoDecr,originalKey);
			//System.out.println(decData);
			JSONObject jodec = new JSONObject(decData);
			ja.put(jodec);

		}


		for (int i = 0; i < ja.length(); i++) {

			// muss die verarbeitung rein
			JSONObject jo = (JSONObject) ja.get(i);

			// RSA_Encryption.decryptString(originalKey,decodedString);
			// hole meinen PrivateKey
			// entschlüssel
			// mach den String zu JSONObject jo

			if (jo.get("id").toString().equals("1")) {
				String filename = jo.get("fileName").toString();
				String keyString = jo.get("data").toString();
				String sender = jo.get("sender").toString();

				// aus Key String sym key entschlüsseln
				// private Key holen
				String privkey = selected.getPrivJSON().get("privatekey").toString();
				//System.out.println(privkey);
				byte[] decodedKey = Base64.getDecoder().decode(keyString);

				SecretKey symkey = RSA_Encryption.decrypt(decodedKey, privkey);

				// key in shared keys speichern
				String sharedKeysAsString = selected.getPrivJSON().get("sharekeys").toString();

				JSONArray sharedKeysAsStringArray = new JSONArray(sharedKeysAsString);
				String keey = Base64.getEncoder().encodeToString(symkey.getEncoded());

				JSONObject oldPrivJSON = selected.getPrivJSON();
				oldPrivJSON.remove("sharekeys");
				JSONObject jof = new JSONObject();

				jof.put("keyName", "SH-key1-" + filename);

				jof.put("key", keey);
				sharedKeysAsStringArray.put(jof);
				oldPrivJSON.put("sharekeys", sharedKeysAsStringArray);

				JSONObject oldPubJSON = selected.getPubJSON();
				String fileKey = oldPubJSON.get("fileKeyMappingList").toString();
				JSONArray fileyKeyListArray = new JSONArray(fileKey);
				String stringForKeyMapping = filename + ":" + "SH-key1-" + filename + ":" + sender;

				fileyKeyListArray.put(stringForKeyMapping);

				oldPubJSON.remove("fileKeyMappingList");
				oldPubJSON.put("fileKeyMappingList", fileyKeyListArray);
				selected.addShareKey(oldPrivJSON, oldPubJSON);

			} else if (jo.get("id").toString().equals("2")) {
				// removeFIleShare

				// remove sharefiles in private
				JSONObject tmp = selected.getPrivJSON();

				String sharekeys = tmp.get("sharekeys").toString();
				JSONArray sharekeyArry = new JSONArray(sharekeys);
				JSONArray newArray = new JSONArray();
				for (int j = 0; j < sharekeyArry.length(); j++) {
					//System.out.println(sharekeyArry);
					String keyName = sharekeyArry.getJSONObject(i).get("keyName").toString().split("-")[2];
					if (keyName.equals(jo.get("data"))) {
						System.out.println("One Access to File got revoked");
					} else {
						newArray.put(jo);

					}
				}

				JSONObject tmp2 = selected.getPubJSON();
				String maplist = tmp2.get("fileKeyMappingList").toString();
				JSONArray mapArray = new JSONArray(maplist);
				JSONArray newMapArray = new JSONArray();
				for (int j = 0; j < mapArray.length(); j++) {
					String tmpString = mapArray.get(i).toString().split(":")[1].split("-")[1];
					if (tmpString.equals(jo.get("data"))) {

					} else {
						newMapArray.put(mapArray.get(i));
					}
				}
				selected.removeShare(newArray, newMapArray);
			} else if (jo.get("id").toString().equals("3")) {
				// removeFIleShare

				// remove sharefiles in private-> f�hrt dazu dass komplettes sharfile gel�scht wird statt geleert->Done
				JSONObject tmp = selected.getPrivJSON();

				String sharekeys = tmp.get("sharekeys").toString();
				JSONArray sharekeyArry = new JSONArray(sharekeys);
				JSONArray newArray = new JSONArray();
				for (int j = 0; j < sharekeyArry.length(); j++) {
					System.out.println(sharekeyArry);
					String keyName = sharekeyArry.getJSONObject(i).get("keyName").toString().split("-")[2];
					if (keyName.equals(jo.get("data"))) {
						System.out.println("One Access to File got revoked");
					} else {
						newArray.put(jo);

					}
				}

				// remove filekeyMappingList
				JSONObject tmp2 = selected.getPubJSON();

				String maplist = tmp2.get("fileKeyMappingList").toString();
				JSONArray mapArray = new JSONArray(maplist);
				JSONArray newMapArray = new JSONArray();
				for (int j = 0; j < mapArray.length(); j++) {

					String tmpString = mapArray.get(i).toString().split(":")[0];
					if (tmpString.equals(jo.get("data"))) {

					} else {
						newMapArray.put(mapArray.get(i));
					}
				}
				selected.removeShare(newArray, newMapArray);
			} else if (jo.get("id").toString().equals("4")) {
				/*
				 * JSONObject bulkObj = new JSONObject(); bulkObj.put("id", 4);
				 * bulkObj.put("data", pubkey); bulkObj.put("cname", cname);
				 * this.addBulk(bulkObj, containerJSON);
				 */
				// hole aus integrityList raus
				// füge ein Array hinzu
				// speicher diese List
				// save container
				JSONObject jopriv = selected.getPrivJSON();
				String integList = jopriv.getString("integritylist").toString();
				JSONArray jainteglist = new JSONArray(integList);
				JSONObject integinfo = new JSONObject();
				integinfo.put("user", jo.get("user"));
				integinfo.put("pubkey", jo.get("data"));
				jainteglist.put(jainteglist);

				selected.addInteger(jainteglist);
			}
		}

		selected.getPubJSON().remove("bulk");
		selected.getPubJSON().put("bulk", "[]");
		selected.resetBulk();
	}

	/**
	 * Allows a File to be shared with a another User by giving him Access. Therefore the Symmetrical Key has to be transmitted in a safe way to the other Users Container.
	 * @param selected
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static void fileShare(Container selected) throws IOException, InvalidKeyException, BadPaddingException,
	IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		try {
			showOwnfile(selected);
		}catch(ClassCastException e) {
			System.out.println("No Files available to share");
			return;
		}


		System.out.println("Which File should be shared?" + "\n" + "('exit' to escape)");
		Scanner so = new Scanner(System.in);
		String filename = so.nextLine();

		String settings = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
		JSONObject userJSON = new JSONObject(settings);
		JSONArray ja = (JSONArray) userJSON.get("users");
		for (int i = 0; i < ja.length(); i++) {
			if(!ja.get(i).toString().contains(selected.getOwner())) {
				System.out.println(ja.get(i).toString().split(":")[0].replaceAll("\"", "").replace("{", ""));
			}
		}
		// TODO Eigener User raus machen
		// TODO USer senden der nicht angzeigt wird
		System.out.println("Who should get Access to this File?");
		String user = so.nextLine();
		// TODO Man kann es sich selbst sharen muss man ändern
		// TODO Fehlerüberprüfung ob User vorhanden ist
		// sende User bulk
		// öffne keychain des Users und füge es in bulk hinzu mit seinem Privat
		// Schlüssel
		// TODO Integrity list
		// check key own integrity list

		/*****************
		 * 
		 * 
		 */

		String settingFile = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
		JSONObject settingJSON = new JSONObject(settingFile);
		ja = new JSONArray(settingJSON.get("users").toString());

		if (!(ja.toString().contains(user))) {
			System.out.println("User does not exist");

		}else if(user.equals(selected.getOwner())) {
			System.out.println("You can not share a File with yourself, but nice try mate ");
		} else {

			String selectedUser = "";
			String containerName = "";
			for (int i = 0; i < ja.length(); i++) {
				selectedUser = ja.getJSONObject(i).toString();
				String newString = selectedUser.replace("{", "").replace("}", "").replaceAll("\"", "");
				String[] splittedSettings = newString.split(":");
				if (user.equals(splittedSettings[0])) {
					selectedUser = splittedSettings[0];
					containerName = splittedSettings[1];
					// User und file in sharedFileList reinmachen

					break;
				}

			}
			JSONObject jouserandFile = new JSONObject();
			jouserandFile.put("user", user);
			jouserandFile.put("file", filename);
			jouserandFile.put("cname", containerName);

			JSONObject privForShareList = selected.getPrivJSON();

			//System.out.println(privForShareList);
			String tmp = privForShareList.get("shareUserList").toString();
			JSONArray jatmp = new JSONArray(tmp);
			jatmp.put(jouserandFile);

			String container=""; 
			try {
				container= new String(Files.readAllBytes(Paths.get(containerName)), StandardCharsets.UTF_8);
			}catch( AccessDeniedException e){
				System.out.println("Invalid Input");
				return;
			}


			JSONObject containerJSON = new JSONObject(container);
			JSONObject open = (JSONObject) containerJSON.get("open");

			String pubkey = open.get("publickey").toString();

			// Symkey holen

			JSONArray filekeymapping = (JSONArray) selected.getPubJSON().get("fileKeyMappingList");
			String contSym = "";
			for (int i = 0; i < filekeymapping.length(); i++) {
				String keys = filekeymapping.getString(i);
				String[] keyArray = keys.split(":");
				if (keyArray[0].equals(filename)) {
					contSym = keyArray[1];
				}
			}
			String sym = "";
			JSONArray files =null; 
					try {
						files =(JSONArray) selected.getPrivJSON().get("filekeys");
					}catch(ClassCastException e) {
						System.out.println("There is no File you could share");
						return;
					}
				
			//System.out.println(files);
			for (int i = 0; i < files.length(); i++) {
				JSONObject jo = (JSONObject) files.get(i);
				if (contSym.equals(jo.get("keyName"))) {

					sym = jo.get("key").toString();
					//System.out.println(sym);
				}

			}
			// String to Bytes
			byte[] decodedKey = Base64.getDecoder().decode(sym);
			sym = null;
			// rebuild key using SecretKeySpec
			SecretKey originalKey=null; 
			try {
				originalKey= new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
			}catch(IllegalArgumentException e){
				System.out.println("There is no File you could share");
				return;
			}

			byte[] encr = RSA_Encryption.encrypt(originalKey, pubkey);
			// byte to string
			String keyforjson = Base64.getEncoder().encodeToString(encr);

			JSONObject bulkObj = new JSONObject();
			bulkObj.put("id", 1);
			bulkObj.put("data", keyforjson);
			bulkObj.put("fileName", filename);
			bulkObj.put("sender", selected.getOwner());
			//System.out.println(open);

			// Bulk hinzufügen
			selected.addBulk(bulkObj, containerJSON);
			// Container Speichern
			selected.addShareUserList(jatmp);
			//System.out.println(selected.getPrivJSON());
		}
	}

	/**
	 * Deletes a existing File in the encrypted Files Destination if the Owner is allowed to do so.
	 * @param selected
	 * @throws IOException
	 */
	private static void deleteFile(Container selected) throws IOException, InvalidKeyException, BadPaddingException,
	IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		JSONArray ja = (JSONArray) selected.getPubJSON().get("fileKeyMappingList");
		for (int i = 0; i < ja.length(); i++) {

			String file = ja.get(i).toString().split(":")[0];
			String creator = ja.get(i).toString().split(":")[2];
			if (selected.getOwner().equals(creator)) {
				System.out.println(i + 1 + ":" + file);
			}
			// System.out.println(i+1+":"+ja.get(i));
		}
		System.out.println("Which File should be deleted?" + "\n" + "('exit' to escape)");
		Scanner so = new Scanner(System.in);
		String filename = so.nextLine();
		boolean match = false;
		// erneute Pruefung ob ich berechtigt bin diese Datei zu loeschen
		for (int i = 0; i < ja.length(); i++) {
			String file = ja.get(i).toString().split(":")[0];
			String autor = ja.get(i).toString().split(":")[2];
			if (file.equals(filename) && autor.equals(selected.getOwner())) {
				match = true;
			}
		}

		// TODO Zweitnutzer darf keine Files des Hauptnutzers l�schen d�rfen

		// key löschen
		// PW Abfrage in Container Klasse
		if (selected.deletekeys(filename) && match) {
			File datei = new File("filesencrypt/" + filename);

			if (datei.delete()) {
				System.out.println("File deleted successfully");
				selected.addDeletedBulkForAll(filename);
			} else {
				System.out.println("File could not be deleted but Reference is deleted");
			}

		} else {
			System.out.println("You are not allowed to delete this File");
		}

		// sendbulktoother
	}
	/**
	 * Shows all available Files of a User to either decrypt or share with another User
	 * @param selected
	 * @return
	 */
	private static void showOwnfile(Container selected) {
		// System.out.println("Testausgabe"+selected.getPubJSON().get("fileKeyMappingList"));
		JSONArray ja = (JSONArray) selected.getPubJSON().get("fileKeyMappingList");
		for (int i = 0; i < ja.length(); i++) {
			String files = ja.get(i).toString();
			String[] a = files.split(":");
			if (a[2].equals(selected.getOwner())) {
				System.out.println(a[0]);
			}

		}

		// TODO check wenn ein benutzer eine EIngabe eingibt die nicht eingezeigt wird
	}

	/**
	 * Opens a chosen File of all available Files of a User.
	 * In Order to use this Option the User is required to enter his password
	 * @param selected
	 */
	private static void openFile(Container selected) {
		// TODO Auto-generated method stub
		// zeig fileKeyMappingList mit nur Files an
		// waehle file aus
		// hole key aus Container
		// entpacke file

		if (!showAvailableFiles(selected)) {
			return;
		}

		// TODO:ich brauche wieder den Symmetischen Key fuer die dazugehoerige Datei
		System.out.println("Which File should be decoded?" + "\n" + "('exit' to escape)");
		Scanner so = new Scanner(System.in);
		String filename = so.nextLine();
		if (filename.equalsIgnoreCase("exit")) {
			return;
		}
		// //Passwort Abfrage
		String pw = AES_Encryption.validatePassword();
		if (!AES_Encryption.verifyPassword(pw)) {
			return;
		} else {

			SecretKey symkey = null;
			try {
				symkey = selected.getKeyFromName(filename);
				File inputFile = new File("filesencrypt/" + filename);

				File decFile = new File("filesdec/" + filename);

				try {
					AES_Encryption.decryptFile(symkey, inputFile, decFile);
				} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
						| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
						| IOException e) {
					System.err.println(e.getMessage());
					e.printStackTrace();

				}
				System.out.println("File decoded");
			} catch (IllegalArgumentException |JSONException |ClassCastException e) {
				System.out.println("File could not be decoded");

			}
		}

	}
	/**
	 * Adds a File which gets encrypted via an generated Key in AES. This Key an File Reference are added to the Users Container
	 * @param container
	 * @throws IOException
	 */
	private static void addFile(Container container) throws IOException

	{
		System.out.println("How should the File be named?" + "\n" + "('exit' to escape)");
		Scanner sc = new Scanner(System.in);
		String filename = sc.nextLine();
		System.out.println("Name of File?");
		String filepath = sc.nextLine();
		if (filepath.equalsIgnoreCase("exit")) {
			return;
		}
		JSONObject file = new JSONObject();

		FileInfo fi = new FileInfo(filename, filepath, container.getOwner());

		// Datei wird verschlüsselt mit einem sym Key
		// Dieser Key wird dann in den Container verschlüsselt gespeichert
		// container.setFileKey();
		// Er wird in das JSON Key gespeichert
		SecretKey symKey = null;
		File inputFile = new File("filesupload/" + filepath);
		File encryptedFile = new File("filesencrypt/" + filename);
		if (!inputFile.isFile()) {
			System.out.println("File could not be found");
			return;
		}
		try {

			// TODO Symmetischer Key muss gespeichert werden
			symKey = AES_Encryption.generateKey(256);

		} catch (NoSuchAlgorithmException e) {
			System.err.print(e.getMessage());
			e.printStackTrace();
		}

		// Gibt true zur�ck ob Passwort Korrekt war, wenn korrekt dann verschl�ssle
		// ansonsten breche ab
		if (!container.addFileKey(symKey, filename)) {
			return;
		}
		// File inputFile = Paths.get(filepath).toFile();
		// System.out.println(inputFile);
		// TODO realtiver Pfad
		// String pfadzumspeichern="files/"+filename;
		// File encryptedFile = new File(pfadzumspeichern);

		try {

			AES_Encryption.encryptFile(symKey, inputFile, encryptedFile);
			inputFile.delete();
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
				| IOException e) {
			System.out.println("File could not be found" + "\n" + "Please enter your Password to remove Reference");
			// TODO Methode nochmal ohne Passwort oder nicht ?
			while (!container.deletekeys(filename))
				;
			return;

		}
		System.out.println("File successfully added");
	}


	/**
	 * Shows all available Files to a User which he can access, this includes all own Files aswell as all shared Files from others he can access.
	 * @param selected
	 * @return
	 */
	private static boolean showAvailableFiles(Container selected) {
		// Zeig alle verfügbaren Files an auf die der User zugreifen darf
		// selbst erstellte Files und share Files sind gekennzeichnet
		JSONArray ja;
		try {
			ja = (JSONArray) selected.getPubJSON().get("fileKeyMappingList");
		} catch (ClassCastException e) {
			System.out.println("No Files available!");
			return false;
		}
		for (int i = 0; i < ja.length(); i++) {
			String files = ja.get(i).toString();
			String[] a = files.split(":");
			System.out.println(a[0]);

		}
		return true;
	}

	/**
	 * Generates a new User and his Container, existing out of a User Name and initial Password
	 * @return
	 * @throws IOException
	 */
	private static Container createUser() throws IOException, InvalidKeyException, BadPaddingException,
	IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		Container selected = null;
		System.out.println("Create User");
		System.out.println("Please enter User Name");
		Scanner sc = new Scanner(System.in);
		String user = sc.nextLine();
		if (user.equals("")) {
			System.out.println("An empty User Name ist not allowed");
			return null;

		} else {
			// Passwort wird initial festgelegt und damit der Privte Part der Json
			// verschl�sselt
			String typedPassword = AES_Encryption.validatePassword();

			// Salt wird aus Settings File ausgelesen
			String settingFile = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
			JSONObject settingJSON = new JSONObject(settingFile);
			String salt = settingJSON.get("appsalt").toString();
			// Hashed Passwort, bestehend aus urspr�nglichem Passwort + Salt;
			String hashedPassword = SHA512.encryptString(typedPassword, salt.getBytes());
			//System.out.println("2: " + hashedPassword);

			// ------------------------------------------------------------------------
			String settings = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
			JSONObject userJSON = new JSONObject(settings);
			JSONArray ja = (JSONArray) userJSON.get("users");
			SimpleDateFormat date = new SimpleDateFormat("yyyy_MM_dd");
			String timeStamp = date.format(new Date());
			String containerName = user + timeStamp + "_" + hashedPassword; // Anhaengen des hashedPassworts TODO
			// Fehlerbei anh�ngen des Hashed PW mit
			// Doppelpunkt
			if (ja.toString().contains("\"" + user + "\":")) {
				System.out.println("User already exists");
			} else {
				userJSON.append("users", new JSONObject().put(user, containerName));
				writeFile(userJSON);
				selected = new Container(containerName, user, typedPassword);

			}

		}
		return selected.getContainer();

	}

	/**
	 * Writes all existing Users to external "Settings.json" File 
	 * @param userJSON
	 * @throws IOException
	 */
	private static void writeFile(JSONObject userJSON) throws IOException {
		FileWriter fw = new FileWriter("settings.json");
		String export = userJSON.toString();
		fw.write(export);
		fw.close();
		System.out.println("User saved");
	}

}
