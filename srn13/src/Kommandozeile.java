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


		Scanner sc = new Scanner(System.in);
		Container selected = null;
		String number ="";

		while(!number.equals("1")&&!number.equals("2")) {
			System.out.println("1: Erstelle User / 2: Login ");
			number=sc.nextLine();
			if(!number.equals("1")&&!number.equals("2")) {
				System.out.println("Ungueltige Eingabe!" + "\n" + "Bitte waehlen Sie einge gueltige Option");
			}
		}

		if (number.equals("1") ) {
			selected = createUser();
		} else if (number.equals("2")) {
			selected = login();
		}
		showAvailableFiles();
		// Nun haben wir einen Container selektiert


		boolean weiter = true;
		while (weiter && selected!=null) {
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
				break;
			}
			default:
				System.out.println("Ungueltige Eingabe!" + "\n" + "Bitte waehlen Sie einge gueltige Option");
				;
			}
		}
		System.out.println("Goodbye");
		System.exit(0);

	}

	// TODO Wenn aktuell ein falsches Password eines Nutzers eingegeben wird kackt
	// die Entschluesselung ab
	private static Container login()
			throws IOException {

		Container c1 = null;
		Scanner sc = new Scanner(System.in);
		String user="";
		while(c1==null) {
			System.out.println("Bitte Username eingeben"+"\n"+"('exit' für verlassen)");

			user = sc.nextLine();
			if(user.equalsIgnoreCase("exit")) {
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

				String finalPassword =AES_Encryption.validatePassword();
				// Hier mï¿½sste ï¿½berprueft werden ob das PW zum User passt oder statt die
				// Exception zu werfen abfangen und wieder zur Eingabe zurï¿½ck springen

				SecretKey aesKey = new SecretKeySpec(finalPassword.getBytes(), "AES");

				String jsonString="";
				try {
					jsonString = AES_Encryption.decrypt(secret, aesKey);
					JSONObject secretJSON = new JSONObject(jsonString);
					JSONObject pubJSON = new JSONObject(containerJSON.get("open").toString());

					c1 = new Container(secretJSON, pubJSON, user);
				} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
						| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {

					//e.printStackTrace();
					System.out.println("Falsches Passwort für hinterlegten Nutzer!");
				}
				// newContainer.put("secret", containerJSON.get("open"));


			}
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
		System.out.println("Welche File soll geloescht werden?"+"\n"+"('exit' für verlassen)");
		Scanner so = new Scanner(System.in);
		String filename = so.nextLine();
		boolean match=false;
		// erneute Prüfung ob ich berechtigt bin diese Datei zu löschen 
		for (int i = 0; i < ja.length(); i++) {
			String file = ja.get(i).toString().split(":")[0];
			if (file.equals(filename)) {
				System.out.println("Hit");
				match=true;
				
				// key lÃ¶schen
				selected.deletekeys(filename);
				File datei = new File("filesencrypt/" + filename);

				if (datei.delete()) {
					System.out.println("File deleted successfully");
				} else {
					System.out.println("Failed to delete the file");
				}
			}

		}
		if(!match) {
			System.out.println("Sie können diese Datei nicht löschen!");
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
		System.out.println("Testausgabe"+selected.getPubJSON().get("fileKeyMappingList"));
		// TODO:ich brauche wieder den Symmetischen Key fuer die dazugehoerige Datei
		System.out.println("Welches Datei soll entschluesselt werden?"+"\n"+"('exit' für verlassen)");
		Scanner so = new Scanner(System.in);
		String filename = so.nextLine();
		if(filename.equalsIgnoreCase("exit")) {
			return;
		}

		SecretKey symkey=null; 
		try {
			symkey= selected.getKeyFromName(filename);
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
			System.out.println("Datei wurde entschlüsselt !");
		}catch(IllegalArgumentException e) {
			System.out.println("Angegebene Datei konnte nicht entschluesselt werden!");
			openFile(selected);
		}


	}

	private static void addFile(Container container) throws IOException

	{
		System.out.println("Wie soll die Datei heiï¿½en?"+"\n"+"('exit' für verlassen)");
		Scanner sc = new Scanner(System.in);
		String filename = sc.nextLine();
		System.out.println("Name der Datei");
		String filepath = sc.nextLine();
		if(filepath.equalsIgnoreCase("exit")) {
			return;
		}
		JSONObject file = new JSONObject();

		FileInfo fi = new FileInfo(filename, filepath, container.getOwner());

		// Datei wird verschlÃ¼sselt mit einem sym Key
		// Dieser Key wird dann in den Container verschlÃ¼sselt gespeichert
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
			System.out.println("Datei konnte nicht gefunden werden!"+"\n"+"Bitte erneut eingeben");
			return;
			
		}
		container.addFileKey(symKey, filename);


	}

	private static void showAvailableFiles() {
		// Zeig alle verfÃ¼gbaren Files an auf die der User zugreifen darf
		// selbst erstellte Files und share Files sind gekennzeichnet

	}

	private static Container createUser() throws IOException {
		Container selected = null;
		System.out.println("Erstelle User");
		System.out.println("Bitte Username eingeben");
		Scanner sc = new Scanner(System.in);
		String user = sc.nextLine();
		if(user.equals("")) {
			System.out.println("Ein leerer Username ist nicht möglich!");
			return null;

		}else {
			//Passwort wird initial festgelegt
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
