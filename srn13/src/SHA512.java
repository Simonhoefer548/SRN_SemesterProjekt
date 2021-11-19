import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SHA512 {
	 
	
	
	public static String encryptString(String toEncrypt, byte[] salt) {

	        String hashedString = null;
	        try {
	            MessageDigest md = MessageDigest.getInstance("SHA-512");
	            md.update(salt);
	            byte[] bytes = md.digest(toEncrypt.getBytes(StandardCharsets.UTF_8));
	            StringBuilder sb = new StringBuilder();
	            for (int i = 0; i < bytes.length; i++) {
	                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
	            }
	            hashedString = sb.toString();
	        } catch (NoSuchAlgorithmException e) {
	            e.printStackTrace();
	        }
	        return hashedString;
	    }

//	    private static byte[] getSalt() throws NoSuchAlgorithmException {
//	        SecureRandom random = new SecureRandom();
//	        byte[] salt = new byte[16];
//	        random.nextBytes(salt);
//	        return salt;
//	    }

	    public static void main(String[] args) throws NoSuchAlgorithmException {

	        // same salt should be passed
	        //Test für Salt von String zu ByteArray und wieder zu String
//	    	String name="testSalttoString";
//			byte[] salt=name.getBytes();
//			String wiederzürück=new String(salt);
//	    	System.out.println(name +"\n"+wiederzürück);
//	    	String key = "Bar12345Bar12345";
//	    	
//	    	Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
//	    	Key aesKey2 = new SecretKeySpec(key.getBytes(), "AES");
//	    	
//	    	if(aesKey.equals(aesKey2)) {
//	    		System.out.println("geht das?");
//	    	}
	    	
	    	KeyPair pair=RSA_Encryption.KeyGenerator();
	    	String encodedKey =Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
	    	System.out.println(encodedKey);
	    	
	    	byte[]decodedKey = Base64.getDecoder().decode(encodedKey);
	    	SecretKey originalKey =new SecretKeySpec(decodedKey,0,decodedKey.length,"RSA");
	    	if(pair.getPublic().equals(originalKey)) {
	    		System.out.println("geht so");
	    	}
//	        String password1 = getSecurePassword("Password", salt);
//	        String password2 = getSecurePassword("Password", salt);
//	        System.out.println(" Password 1 -> " + password1);
//	        System.out.println(" Password 2 -> " + password2);
//	        if (password1.equals(password2)) {
//	            System.out.println("passwords are equal");
	        //}
	    }
	}

