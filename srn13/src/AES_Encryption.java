

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class AES_Encryption {
	
	public static String validatePassword() {
		Scanner sc = new Scanner(System.in);
		String inputPW = "";
		String finalPW = "";
		
		  do {
		  System.out.println("Bitte Passwort eingeben"+"\n"+"(Zwischen 1-16 Zeichen)");
		  inputPW=sc.nextLine(); if(inputPW.length()>0 || inputPW.length() >16) {
		  finalPW=AES_Encryption.extendGivenPassword(inputPW); }
		  
		  }while(inputPW.length()==0 || inputPW.length() >=16);
		  
		 
		// TODO syos wieder entfernen, nur zum testen
		System.out.println("Dein gespeichertes Passwort lautet: " + finalPW + "\n"
				+ "(Kann auf 16 Stellen erweitert worden sein!)" + System.lineSeparator());
		return finalPW;

	}
	

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
        cipher.init(Cipher.DECRYPT_MODE, key);//iv
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
