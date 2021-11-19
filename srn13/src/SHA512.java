import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

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
	        //Test f�r Salt von String zu ByteArray und wieder zu String
	    	String name="testSalttoString";
			byte[] salt=name.getBytes();
			String back=new String(salt);
	    	System.out.println(name +"\n"+back);
	    	
//	        String password1 = getSecurePassword("Password", salt);
//	        String password2 = getSecurePassword("Password", salt);
//	        System.out.println(" Password 1 -> " + password1);
//	        System.out.println(" Password 2 -> " + password2);
//	        if (password1.equals(password2)) {
//	            System.out.println("passwords are equal");
	        //}
	    }
	}

