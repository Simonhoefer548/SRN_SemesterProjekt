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

		Scanner selection = new Scanner(System.in);
		Container selected = null;
		int number = selection.nextInt();
		if (number == 1) {
			selected = createUser();
		} else if (number == 2) {
			selected = login();
		} else {
			System.out.println("Ung�ltige Eingabe!" + "\n" + "Bitte w�hlen Sie einge g�ltige Option");
		}
		System.out.println(selected.getFullJSON());
		showAvailableFiles();
		// Nun haben wir einen Container selektiert
		System.out.println("Optionen");
		System.out.println("1.Add File / 2. Open File / 3.Delete File / 4. File Share / 5. Exit ");
		Scanner opt = new Scanner(System.in);
		number = opt.nextInt();
		boolean weiter = true;
		while (weiter) {
			switch (number) {
			case 1: {
				// File verschlüsseln
				addFile(selected);
			}
			case 2: {
				openFile(selected);
				;
			}
			case 3: {
				deleteFile(selected);
				// nur wenn der ersteller
				;
			}
			case 4: {
				fileShare(selected);
				// Nur der ersteller kann File share einer Datei einstellen
				// Hier werden nur Files angezeigt die selber hinzugefügt wurden
				// Hier können wir ein FIle auswählen und dann User FIle zugriff geben oder
				// nicht
				;
			}
			case 5: {
				System.out.println("Goodbye");
				weiter = false;
			}
			default:
				System.out.println("Ung�ltige Eingabe!" + "\n" + "Bitte w�hlen Sie einge g�ltige Option");
				;
			}
		}

	}

	private static Container login()
			throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		System.out.println("Name?");
		Scanner userName = new Scanner(System.in);
		String user = userName.nextLine();
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
			System.out.println("Pw?");
			Scanner pw = new Scanner(System.in);
			String password = userName.nextLine();
			SecretKey aesKey = new SecretKeySpec(password.getBytes(), "AES");
			String jsonString = AES_Encryption.decrypt(secret, aesKey);
			System.out.println(jsonString);
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

	private static void deleteFile(Container selected) {
		// TODO Auto-generated method stub
		// showOwnfile();
		// wähle file aus
		// lösche keys und file

	}

	private static List<String> showOwnfile(Container selected) {
		// TODO Auto-generated method stub
		return null;
	}

	private static void openFile(Container selected) {
		// TODO Auto-generated method stub
		// zeig fileKeyMappingList mit nur Files an
		// wähle file aus
		// hole key aus Container
		// entpacke file

		// TODO:ich brauche wieder den Symmetischen Key f�r die dazugeh�rige Datei
		SecretKey symkey = null;
		// TODO ich brauche den Pfad der zu entschl�ssenden Datei
		String filepath = "";

		File encryptedFile = Paths.get(filepath).toFile();
		File DedcryptedFile = new File(filepath + "Decrypted");

		try {
			AES_Encryption.decryptFile(symkey, encryptedFile, DedcryptedFile);
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
				| IOException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
		}

	}

	private static void addFile(Container container) {
		System.out.println("Wie soll die Datei hei�en?");
		Scanner sc = new Scanner(System.in);
		String filename = sc.nextLine();
		System.out.println("Pfad zur Datei");
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
			container.addFileKey(symKey,filename);
		
		} catch (NoSuchAlgorithmException e) {
			System.err.print(e.getMessage());
			e.printStackTrace();
		}

		File inputFile = Paths.get(filepath).toFile();
		//TODO realtiver Pfad
		String pfadzumspeichern="files/"+filename;
		File encryptedFile = new File(pfadzumspeichern);
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
		System.out.println("Name?");
		Scanner userName = new Scanner(System.in);
		String user = userName.nextLine();
		// TODO pw auf L�nge pr�fen und gegebenfalls auf 16 Stellen erweitern
		System.out.println("Pw?: (Genau 16 Zeichen!)");
		Scanner pw = new Scanner(System.in);
		String password = userName.nextLine();
		String settings = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
		JSONObject userJSON = new JSONObject(settings);
		JSONArray ja = (JSONArray) userJSON.get("users");
		SimpleDateFormat date = new SimpleDateFormat("yyyy_MM_dd");
		String timeStamp = date.format(new Date());
		String containerName = user + timeStamp;
		if (ja.toString().contains("\"" + user + "\":")) {
			System.out.println("User schon vorhanden du Bastard");
		} else {
			userJSON.append("users", new JSONObject().put(user, containerName));
			writeFile(userJSON);
			selected = new Container(containerName, user, password);

		}

		return selected.getContainer();

	}

	private static void writeFile(JSONObject userJSON) throws IOException {
		FileWriter fw = new FileWriter("settings.json");
		String export = userJSON.toString();
		fw.write(export);
		fw.close();
		System.out.println("Ver�ndert");
	}
}
