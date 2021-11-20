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
		System.out.println("1: Erstelle User / 2: Login ");

		Scanner sc = new Scanner(System.in);
		Container selected = null;
		int number = sc.nextInt();
		if (number == 1) {
			selected = createUser();
		} else if (number == 2) {
			selected = login();
		} else {
			System.out.println("Ungueltige Eingabe!" + "\n" + "Bitte waehlen Sie einge gueltige Option");
		}
		showAvailableFiles();
		// Nun haben wir einen Container selektiert
		System.out.println("Optionen");
		System.out.println("1.Add File / 2. Open File / 3.Delete File / 4. File Share / 5. Exit ");
		number = sc.nextInt();
		boolean weiter = true;
		while (weiter) {

			switch (number) {
			case 1: {
				// File verschluesseln
				addFile(selected);
				number = 5;
				break;
			}
			case 2: {
				openFile(selected);
				number = 5;
				break;

			}
			case 3: {
				deleteFile(selected);
				// nur wenn der ersteller
				break;
			}
			case 4: {
				fileShare(selected);
				// Nur der ersteller kann File share einer Datei einstellen
				// Hier werden nur Files angezeigt die selber hinzugefuegt wurden
				// Hier koennen wir ein File auswaehlen und dann User File Zugriff geben oder
				// nicht
				break;
			}
			case 5: {
				System.out.println("Goodbye");
				weiter = false;
				break;
			}
			default:
				System.out.println("Ungueltige Eingabe!" + "\n" + "Bitte waehlen Sie einge gueltige Option");
				;
			}
		}

	}

	// TODO Wenn aktuell ein falsches Password eines Nutzers eingegeben wird kackt
	// die Entschluesselung ab
	private static Container login()
			throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		System.out.println("Bitte Username eingeben");
		Scanner sc = new Scanner(System.in);
		String user = sc.nextLine();
		Container c1 = null;

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

			String finalPassword = validatePassword();
			// Hier m�sste �berprueft werden ob das PW zum User passt oder statt die
			// Exception zu werfen abfangen und wieder zur Eingabe zur�ck springen

			SecretKey aesKey = new SecretKeySpec(finalPassword.getBytes(), "AES");

			String jsonString = AES_Encryption.decrypt(secret, aesKey);
			// newContainer.put("secret", containerJSON.get("open"));
			JSONObject secretJSON = new JSONObject(jsonString);
			JSONObject pubJSON = new JSONObject(containerJSON.get("open").toString());

			c1 = new Container(secretJSON, pubJSON, user);

		}

		return c1;
	}

	private static void fileShare(Container selected) {
		// TODO Auto-generated method stub
		// showOwnfile();
		// Key austausch
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
		System.out.println("Welches Files? Gib Name an");
		Scanner so = new Scanner(System.in);
		String filename = so.nextLine();
		// key löschen
		selected.deletekeys(filename);
		File file = new File("filesencrypt/" + filename);

		if (file.delete()) {
			System.out.println("File deleted successfully");
		} else {
			System.out.println("Failed to delete the file");
		}
		
		
		//sendbulktoother


	}

	private static List<String> showOwnfile(Container selected) {
		// TODO Auto-generated method stub
		return null;
	}

	private static void openFile(Container selected) {
		// TODO Auto-generated method stub
		// zeig fileKeyMappingList mit nur Files an
		// waehle file aus
		// hole key aus Container
		// entpacke file
		System.out.println(selected.getPubJSON().get("fileKeyMappingList"));
		// TODO:ich brauche wieder den Symmetischen Key fuer die dazugehoerige Datei
		System.out.println("Welches Files? Gib Name an");
		Scanner so = new Scanner(System.in);
		String filename = so.nextLine();
		SecretKey symkey = selected.getKeyFromName(filename);

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

	}

	private static void addFile(Container container) throws IOException {
		System.out.println("Wie soll die Datei hei�en?");
		Scanner sc = new Scanner(System.in);

		String filename = sc.nextLine();
		System.out.println("Name der Datei");
		String filepath = sc.nextLine();

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
			container.addFileKey(symKey, filename);

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
			System.err.print(e.getMessage());
			e.printStackTrace();
		}

		sc.close();

	}

	private static void showAvailableFiles() {
		// Zeig alle verfügbaren Files an auf die der User zugreifen darf
		// selbst erstellte Files und share Files sind gekennzeichnet

	}

	private static Container createUser() throws IOException {
		Container selected = null;
		System.out.println("Erstelle User");
		System.out.println("Bitte Username eingeben");
		Scanner sc = new Scanner(System.in);
		String user = sc.nextLine();
		String finalPassword = validatePassword();
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

		return selected.getContainer();

	}

	private static void writeFile(JSONObject userJSON) throws IOException {
		FileWriter fw = new FileWriter("settings.json");
		String export = userJSON.toString();
		fw.write(export);
		fw.close();
		System.out.println("Veraendert");
	}

	private static String validatePassword() {
		Scanner sc = new Scanner(System.in);
		String inputPW = "";
		String finalPW = "";
		/*
		 * do {
		 * System.out.println("Bitte Passwort eingeben"+"\n"+"(Zwischen 1-16 Zeichen)");
		 * inputPW=sc.nextLine(); if(inputPW.length()>0 || inputPW.length() >16) {
		 * finalPW=AES_Encryption.extendGivenPassword(inputPW); }
		 * 
		 * }while(inputPW.length()==0 || inputPW.length() >=16);
		 * 
		 */
		// TODO syos wieder entfernen, nur zum testen
		System.out.println("Dein gespeichertes Passwort lautet: " + finalPW + "\n"
				+ "(Kann auf 16 Stellen erweitert worden sein!)" + System.lineSeparator());
		return sc.nextLine();

	}
}
