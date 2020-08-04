import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AES 
{
	String id, rcvr, encMsg, key;
	
	SecretKey secretKey, tmp;
	KeySpec spec;
	SecretKeyFactory skf;
	Cipher cipher;
	
	byte []message, dec, keyBytes;
	String enc;
	
	public AES(String id, String status) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException
	{
		this.id = id;
		
		if (status != "challenge")
		{
			System.out.println("Let's generate secret key for "+id+" ...");
			
//			r = new Random();
//		
//			byte bytes[] = new byte[16]; // 128 bits > 16 bytes;
//			r.nextBytes(bytes);
//			key = r.toString();
			
			BigInteger k = new BigInteger(255,new SecureRandom());
			key = k.toString();
			System.out.println("MY SECRET KEY:"+key);
			generatKey(key);
		}
		else
		{
			System.out.println("Welcome Entity:"+id+" in AES");
		}
		
	}
	
	public void generatKey(String key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException
	{	
		skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		spec = new PBEKeySpec(key.toCharArray(), key.getBytes(), 128, 256);
		tmp = skf.generateSecret(spec);
		secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
		cipher = Cipher.getInstance("AES");
	}
	
	public String getSecretKey()
	{
		return key;
	}
	
	public String enc(String key, String M) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, UnsupportedEncodingException
	{
		generatKey(key);
		
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	    
	    byte[] cipherText = cipher.doFinal(M.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(cipherText);
	}
	
	public String dec(String key, String C) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException
	{
		generatKey(key);
		
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		
		byte[] cipherText = cipher.doFinal(Base64.getDecoder().decode(C));
		
		System.out.println("Entity:"+id+"  decrypted Msg:"+new String(cipherText)+"  with Key:"+key);
        return new String(cipherText);
	}
}
