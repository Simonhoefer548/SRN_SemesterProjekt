import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONObject;

public class Kommandozeile {

	public static void main(String[] args)
			throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		System.out.println("Optionen");

		Scanner sc = new Scanner(System.in);
		Container selected = null;
		String number = "";

		while (!number.equals("1") && !number.equals("2")) {
			System.out.println("1: Erstelle User / 2: Login ");
			number = sc.nextLine();
			if (!number.equals("1") && !number.equals("2")) {
				System.out.println("Ungueltige Eingabe!" + "\n" + "Bitte waehlen Sie einge gueltige Option");
			}
		}

		if (number.equals("1")) {
			selected = createUser();
		} else if (number.equals("2")) {
			selected = login();
		}
		// Nun haben wir einen Container selektiert
		verarbeiteBulk(selected);
		boolean weiter = true;
		while (weiter && selected != null) {

			System.out.println("Optionen");
			System.out.println("1.Add File / 2. Open File / 3.Delete File / 4. File Share / 5. Exit ");
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
				weiter = false;
				selected = null;
				break;
			}
			default:
				System.out.println("Ungueltige Eingabe!" + "\n" + "Bitte waehlen Sie einge gueltige Option");
				;
			}
		}
		System.out.println("Goodbye");

	}

	// TODO Wenn aktuell ein falsches Password eines Nutzers eingegeben wird kackt
	// die Entschluesselung ab
	private static Container login() throws IOException {

		Container c1 = null;
		Scanner sc = new Scanner(System.in);
		String user = "";
		while (c1 == null) {
			System.out.println("Bitte Username eingeben" + "\n" + "('exit' f�r verlassen)");

			user = sc.nextLine();
			if (user.equalsIgnoreCase("exit")) {
				return null;
			}

			String settingFile = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
			JSONObject settingJSON = new JSONObject(settingFile);
			JSONArray ja = new JSONArray(settingJSON.get("users").toString());

			if (!(ja.toString().contains(user))) {
				System.out.println("User nicht vorhanden ");

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

				System.out.println(secret);

				String finalPassword = AES_Encryption.validatePassword();
				// Hier m�sste �berprueft werden ob das PW zum User passt oder statt die
				// Exception zu werfen abfangen und wieder zur Eingabe zur�ck springen

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
					System.out.println("Falsches Passwort f�r hinterlegten Nutzer!");
				}
				// newContainer.put("secret", containerJSON.get("open"));

			}
		}
		return c1;
	}

	private static void verarbeiteBulk(Container selected) throws InvalidKeyException, NoSuchPaddingException,
			NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException {
		String test = selected.getPubJSON().get("bulk").toString();
		JSONArray ja = new JSONArray(test);
		for (int i = 0; i < ja.length(); i++) {
			JSONObject jo = (JSONObject) ja.get(i);
			if (jo.get("id").toString().equals("1")) {
				String filename = jo.get("fileName").toString();
				String keyString = jo.get("data").toString();
				String sender = jo.get("sender").toString();

				// aus Key String sym key entschlüsseln
				// private Key holen
				String privkey = selected.getPrivJSON().get("privatekey").toString();

				byte[] decodedKey = Base64.getDecoder().decode(keyString);

				SecretKey symkey = RSA_Encryption.decrypt(decodedKey, privkey);

				// key in shared keys speichern
				String sharedKeysAsString = selected.getPrivJSON().get("sharekeys").toString();
				JSONArray sharedKeysAsStringArray = new JSONArray(sharedKeysAsString);
				String keey = Base64.getEncoder().encodeToString(symkey.getEncoded());

				JSONObject oldPrivJSON = selected.getPrivJSON();
				oldPrivJSON.remove("sharekeys");
				JSONObject jof = new JSONObject();
				jof.put("keyName",  "SH-key1-" + filename );
				jof.put("key", keey);
				sharedKeysAsStringArray.put(jof);
				oldPrivJSON.put("sharekeys", sharedKeysAsStringArray);

				JSONObject oldPubJSON = selected.getPubJSON();
				String fileKey = oldPubJSON.get("fileKeyMappingList").toString();
				JSONArray fileyKeyListArray = new JSONArray(fileKey);
				// test1:S-key1-test1:luca
				String stringForKeyMapping = filename + ":" + "SH-key1-" + filename + ":" + sender;

				fileyKeyListArray.put(stringForKeyMapping);

				oldPubJSON.remove("fileKeyMappingList");
				oldPubJSON.put("fileKeyMappingList", fileyKeyListArray);
				selected.addShareKey(oldPrivJSON, oldPubJSON);

			}
		}
		// TODO Muss wieder einkommentiert werden

		selected.getPubJSON().remove("bulk");
		selected.getPubJSON().put("bulk", "[]");
		selected.resetBulk();
	}

	private static void fileShare(Container selected) throws IOException, InvalidKeyException, BadPaddingException,
			IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
		showOwnfile(selected);
		System.out.println("Welche File soll geshared werden?" + "\n" + "('exit' f�r verlassen)");
		Scanner so = new Scanner(System.in);
		String filename = so.nextLine();

		String settings = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
		JSONObject userJSON = new JSONObject(settings);
		JSONArray ja = (JSONArray) userJSON.get("users");
		for (int i = 0; i < ja.length(); i++) {
			System.out.println(ja.get(i).toString().split(":")[0].replaceAll("\"", "").replace("{", ""));

		}
		// TODO Eigener User raus machen
		// TODO USer senden der nicht angzeigt wird
		System.out.println("An wen soll es geshared werden?");
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
			System.out.println("User nicht vorhanden ");

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
			JSONArray files = (JSONArray) selected.getPrivJSON().get("filekeys");
			System.out.println(files);
			for (int i = 0; i < files.length(); i++) {
				JSONObject jo = (JSONObject) files.get(i);
				if (contSym.equals(jo.get("keyName"))) {

					sym = jo.get("key").toString();
					System.out.println(sym);
				}

			}
			// String to Bytes
			byte[] decodedKey = Base64.getDecoder().decode(sym);
			sym = null;
			// rebuild key using SecretKeySpec
			SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

			byte[] encr = RSA_Encryption.encrypt(originalKey, pubkey);
			// byte to string
			String keyforjson = Base64.getEncoder().encodeToString(encr);

			JSONObject bulkObj = new JSONObject();
			bulkObj.put("id", 1);
			bulkObj.put("data", keyforjson);
			bulkObj.put("fileName", filename);
			bulkObj.put("sender", selected.getOwner());
			System.out.println(open);

			selected.addBulk(bulkObj, containerJSON);

		}
	}

	private static void deleteFile(Container selected) throws IOException {
		JSONArray ja = (JSONArray) selected.getPubJSON().get("fileKeyMappingList");
		for (int i = 0; i < ja.length(); i++) {

			String file = ja.get(i).toString().split(":")[0];
			String creator = ja.get(i).toString().split(":")[2];
			if (selected.getOwner().equals(creator)) {
				System.out.println(i + 1 + ":" + file);
			}
			// System.out.println(i+1+":"+ja.get(i));
		}
		System.out.println("Welche File soll geloescht werden?" + "\n" + "('exit' f�r verlassen)");
		Scanner so = new Scanner(System.in);
		String filename = so.nextLine();
		boolean match = false;
		// erneute Pr�fung ob ich berechtigt bin diese Datei zu l�schen
		for (int i = 0; i < ja.length(); i++) {
			String file = ja.get(i).toString().split(":")[0];
			if (file.equals(filename)) {
				System.out.println("Hit");
				match = true;

				// key löschen
				selected.deletekeys(filename);
				File datei = new File("filesencrypt/" + filename);

				if (datei.delete()) {
					System.out.println("File deleted successfully");
				} else {
					System.out.println("Failed to delete the file");
				}
			}

		}
		if (!match) {
			System.out.println("Sie k�nnen diese Datei nicht l�schen!");
		}

		// sendbulktoother

	}

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

	private static void openFile(Container selected) {
		// TODO Auto-generated method stub
		// zeig fileKeyMappingList mit nur Files an
		// waehle file aus
		// hole key aus Container
		// entpacke file
		showAvailableFiles(selected);
		// TODO:ich brauche wieder den Symmetischen Key fuer die dazugehoerige Datei
		System.out.println("Welches Datei soll entschluesselt werden?" + "\n" + "('exit' f�r verlassen)");
		Scanner so = new Scanner(System.in);
		String filename = so.nextLine();
		if (filename.equalsIgnoreCase("exit")) {
			return;
		}

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
			System.out.println("Datei wurde entschl�sselt !");
		} catch (IllegalArgumentException e) {
			System.out.println("Angegebene Datei konnte nicht entschluesselt werden!");
			openFile(selected);
		}

	}

	private static void addFile(Container container) throws IOException

	{
		System.out.println("Wie soll die Datei hei�en?" + "\n" + "('exit' f�r verlassen)");
		Scanner sc = new Scanner(System.in);
		String filename = sc.nextLine();
		System.out.println("Name der Datei");
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
		try {

			// TODO Symmetischer Key muss gespeichert werden
			symKey = AES_Encryption.generateKey(256);

		} catch (NoSuchAlgorithmException e) {
			System.err.print(e.getMessage());
			e.printStackTrace();
		}

		File inputFile = new File("filesupload/" + filepath);
		File encryptedFile = new File("filesencrypt/" + filename);

		// File inputFile = Paths.get(filepath).toFile();
		// System.out.println(inputFile);
		// TODO realtiver Pfad
		// String pfadzumspeichern="files/"+filename;
		// File encryptedFile = new File(pfadzumspeichern);

		try {

			AES_Encryption.encryptFile(symKey, inputFile, encryptedFile);
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
				| IOException e) {
			System.out.println("Datei konnte nicht gefunden werden!" + "\n" + "Bitte erneut eingeben");
			return;

		}
		container.addFileKey(symKey, filename);

	}

	private static void showAvailableFiles(Container selected) {
		// Zeig alle verfügbaren Files an auf die der User zugreifen darf
		// selbst erstellte Files und share Files sind gekennzeichnet
		JSONArray ja = (JSONArray) selected.getPubJSON().get("fileKeyMappingList");
		for (int i = 0; i < ja.length(); i++) {
			String files = ja.get(i).toString();
			String[] a = files.split(":");
			System.out.println(a[0]);

		}

	}

	private static Container createUser() throws IOException {
		Container selected = null;
		System.out.println("Erstelle User");
		System.out.println("Bitte Username eingeben");
		Scanner sc = new Scanner(System.in);
		String user = sc.nextLine();
		if (user.equals("")) {
			System.out.println("Ein leerer Username ist nicht m�glich!");
			return null;

		} else {
			// Passwort wird initial festgelegt
			String finalPassword = AES_Encryption.validatePassword();
			String settings = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
			JSONObject userJSON = new JSONObject(settings);
			JSONArray ja = (JSONArray) userJSON.get("users");
			SimpleDateFormat date = new SimpleDateFormat("yyyy_MM_dd");
			String timeStamp = date.format(new Date());
			String containerName = user + timeStamp;
			if (ja.toString().contains("\"" + user + "\":")) {
				System.out.println("User bereits vorhanden");
			} else {
				userJSON.append("users", new JSONObject().put(user, containerName));
				writeFile(userJSON);
				selected = new Container(containerName, user, finalPassword);

			}

		}
		return selected.getContainer();

	}

	private static void writeFile(JSONObject userJSON) throws IOException {
		FileWriter fw = new FileWriter("settings.json");
		String export = userJSON.toString();
		fw.write(export);
		fw.close();
		System.out.println("Veraendert");
	}

}
