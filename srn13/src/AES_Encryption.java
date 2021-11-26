

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

public class AES_Encryption {
	
	/**
	 * Reads a password from Keyboard, it has to be greater then 0 Characters and smaller then 16 Characters
	 * @return
	 */
	public static String validatePassword() {
		Scanner sc = new Scanner(System.in);
		String inputPW = "";
		String finalPW = "";

		do {
			System.out.println("Please enter your Password"+"\n"+"(Between  1-16 Characters)");
			inputPW=sc.nextLine(); if(inputPW.length()>0 || inputPW.length() >16) {
				finalPW=AES_Encryption.extendGivenPassword(inputPW); }

		}while(inputPW.length()==0 || inputPW.length() >=16);

		return finalPW;

	}

	/**
	 * If a given Password does not have the length of 16 Characters this Method will fill the missing Chars with zeros
	 * @param givenPassword
	 * @return
	 */
	public static String extendGivenPassword(String givenPassword) {
		int neededLength=16;
		int charsToExtend=neededLength-givenPassword.length();
		//System.out.println("Um wie viele Stellen muss erweitert werden "+charsToExtend);
		String extendedPassword=givenPassword;
		for(int i=0;i<charsToExtend;i++) {
			extendedPassword+="0";
		}
		return extendedPassword;

	}	
	/**
	 * Hashes input Password to compare it with hashed Password saved in Containername 
	 * @param inputPW
	 * @return
	 */
	public static boolean verifyPassword(String inputPW) {
		//Passwortabfrage

		// Salt aus Settings Json ziehen
		String settingFile="";
		try {
			settingFile = new String(Files.readAllBytes(Paths.get("settings.json")), StandardCharsets.UTF_8);
		} catch (IOException e) {
			System.err.print(e.getMessage());
			e.printStackTrace();
		}
		JSONObject settingJSON = new JSONObject(settingFile);
		JSONArray users = new JSONArray(settingJSON.get("users").toString());
		String salt = settingJSON.get("appsalt").toString(); 		
		//User Pw mit Salt hashen
		String passwordToCompare=SHA512.encryptString(inputPW, salt.getBytes());
		// gehashtes User Passwort mit in Container stehendem Hash vergleichen
		if(!(users.toString().contains(passwordToCompare))) {
			System.out.println("Incorrect Password!");
			return false;
		}else {
			return true;
		}



	}
	/**
	 * @param input
	 * @param key
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String encrypt(String input, SecretKey key)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherText = cipher.doFinal(input.getBytes());
		return Base64.getEncoder()
				.encodeToString(cipherText);
	}

	/**
	 * @param cipherText
	 * @param key
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String decrypt(String cipherText, SecretKey key)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] plainText = cipher.doFinal(Base64.getDecoder()
				.decode(cipherText));
		return new String(plainText);
	}



	/**
	 * @param n Defines the Strength of the Key
	 * @return Symmetric Key to en-and decode a File 
	 * @throws NoSuchAlgorithmException
	 */
	public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(n);
		SecretKey key = keyGenerator.generateKey();
		return key;
	}

	/**
	 * @param key: need a given symmetrical Key to encode File
	 * @param inputFile: need a given File do Encode
	 * @param outputFile: needs a Path to save the newly encrypted File, you can´t override the old File because of buffering Stream
	 * @throws IOException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static void encryptFile(SecretKey key,File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
	NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
	BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);//iv 
		FileInputStream inputStream = new FileInputStream(inputFile);
		FileOutputStream outputStream = new FileOutputStream(outputFile);
		byte[] buffer = new byte[64];
		int bytesRead;
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			byte[] output = cipher.update(buffer, 0, bytesRead);
			if (output != null) {
				outputStream.write(output);
			}
		}
		byte[] outputBytes = cipher.doFinal();
		if (outputBytes != null) {
			outputStream.write(outputBytes);
		}
		inputStream.close();
		outputStream.close();
	}

	/**
	 * @param key: need a given symmetrical Key to decode File
	 * @param encryptedFile: need a given File do decode
	 * @param decryptedFile:needs a Path to save the newly decrypted File
	 * @throws IOException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static void decryptFile(SecretKey key,File encryptedFile, File decryptedFile) throws IOException, NoSuchPaddingException,
	NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
	BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		FileInputStream inputStream = new FileInputStream(encryptedFile);
		FileOutputStream outputStream = new FileOutputStream(decryptedFile);
		byte[] buffer = new byte[64];
		int bytesRead;
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			byte[] output = cipher.update(buffer, 0, bytesRead);
			if (output != null) {
				outputStream.write(output);
			}
		}
		byte[] output = cipher.doFinal();
		if (output != null) {
			outputStream.write(output);
		}
		inputStream.close();
		outputStream.close();
	}


}
