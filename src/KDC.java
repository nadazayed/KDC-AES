import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class KDC 
{
	String sndr, rcvr, M, KS;
	int N;
	String[] s;

	Random r;
	AES aes;
	
	static HashMap<String, String> entities = new HashMap();
	
	public KDC(String id) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException
	{
		System.out.println("Welcome Entity:"+id+" in KDC");
		
		aes = new AES(id, "KDC");
		r = new Random();
		
		this.sndr = id;
		
		entities.put(id, aes.getSecretKey());
		System.out.println("Entity:"+id+" registered in KDC successfully");
	}
	
	public String getSecretKey()
	{
		return aes.getSecretKey();
	}
	
	public boolean check (String entity)
	{
		if (entities.containsKey(entity))
			return true;
		else
			return false;
	}
	
	public String connectTo (String M) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, UnsupportedEncodingException
	{
		s = M.split(",");
		sndr = s[0];
		rcvr = s[1];
		N = Integer.parseInt(s[2]);
		System.out.println("Entity:"+s[0]+" connected with:"+s[1]+" with N:"+N+"\n");
		
		//Encrypt inner part with rcvr key Kb
		M = generateSessionKey()+","+sndr; //Ks || IDA
		String innerEnc = aes.enc(entities.get(rcvr),M); //EKb[Ks||IDA]]

		//Encrypt outer part with sndr key
		M = KS+","+rcvr+","+N+","+innerEnc; //KS || IDB || N || EKb[Ks||IDA]]
		String outerEnc = aes.enc(entities.get(sndr), M); //EKA[KS || IDB || N|| EKb[Ks||IDA]]]
		
		return outerEnc;
	}
	
	public void comm (String status, String M) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, UnsupportedEncodingException
	{
		if (status == "challengeB") 
		{
			M = KS+","+M;
			String challenge = aes.enc(entities.get(rcvr), M);
		}
	}
	
	public String generateSessionKey()
	{
		BigInteger k = new BigInteger(255,new SecureRandom());
		KS = k.toString();
		
		System.out.println("OUR SESSION KEY:"+KS);
		return KS;
	}
}
