import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Entity 
{
	String id, encMsg, decMsg, challengeKDC, rcvr, mySecretKey, SessionKey;
	String N;
	
	KDC kdc;
	Random r;
	AES aes;
	
	public Entity(String id) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException
	{
		System.out.println("Welcome entity:"+id);
		this.id = id;
		r = new Random();
		
		aes = new AES(id, "challenge");
		kdc = new KDC (id);
		
		mySecretKey = kdc.getSecretKey();
	}
	
	public void generateNonce()
	{
		int min = 1;
		int max = 100;
		N = (new BigInteger (String.valueOf(r.nextInt((max - min) + 1) + min))).toString();
//		N = r.nextInt();
		System.out.println("Nonce value generated for "+id+": "+N);
	}
	
	public void connectToKDC (String rcvr) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, UnsupportedEncodingException
	{
//		this.rcvr = rcvr;
		System.out.println("Sending to KDC [IDA || IDB || N1] ...");
		if (!kdc.check(rcvr))
			System.out.println("Entity:"+rcvr+" not found");
		else
		{
			System.out.println("Entity:"+id+" trying to connect to Entity:"+rcvr+" ...");
			
			String M = id+","+rcvr+","+N; //IDA || IDB || N1
			challengeKDC = kdc.connectTo(M);
			System.out.println("KDC replied\n");
			
			decMsg = aes.dec(mySecretKey, challengeKDC);
			
			String[] s = decMsg.split(",");
			SessionKey = s[0];
//			System.out.println("KDC Msg: "+decMsg);
		}
	}
	
	//assume A
	public String challengeI(String rcvr) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException
	{
		System.out.println("Entity:"+id+" challenging Entity:"+rcvr+" ...");
		
		String[] s = decMsg.split(",");
		System.out.println("Send KDC decrypted reply with EKb:"+s[s.length-1]);
		
		return s[s.length-1];
	}
	
	//assume B
	public void acceptChallengeI(String rcvr, String M) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException
	{
		System.out.println("Entity:"+id+" accept challenge of Entity:"+rcvr+" ...");
		System.out.println("Challenge EKb[KS || IDA]: "+M); //EKb[Ks || IDA]
		
		decMsg = aes.dec(mySecretKey, M);
		System.out.println("Challenge content KS||IDA: "+decMsg);
		
		String[] s = decMsg.split(",");
		SessionKey = s[0];
	}
	
	//assume B
	public String challengeII(String rcvr) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, UnsupportedEncodingException
	{
		System.out.println("Entity:"+id+" challenging Entity:"+rcvr+" ...");
		generateNonce();
		String M = N+"";
		encMsg = aes.enc(SessionKey, M);
		return encMsg;
	}
	
	//assume A
	public void acceptChallengeII(String rcvr, String M) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException
	{
		System.out.println("Entity:"+id+" accept challenge of Entity:"+rcvr+" ...");
		System.out.println("Challenge EKS[N]: "+M); //EKS[N]
		
		decMsg = aes.dec(SessionKey, M);
		System.out.println("Challenge content N2: "+decMsg);
	}
	
	//assume A
	public String challengeIII(String rcvr) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, UnsupportedEncodingException
	{
		System.out.println("Entity:"+id+" challenging Entity:"+rcvr+" ...");
		String M = (Integer.parseInt(decMsg) * 200) + "";
		encMsg = aes.enc(SessionKey, M);
		System.out.println("Apply f(N2 * 200)");
		return encMsg;
	}
	
	public void acceptChallengeIII(String rcvr, String M) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException
	{
		System.out.println("Entity:"+id+" accept challenge of Entity:"+rcvr+" ...");
		
		System.out.println("Challenge EKSf[N]: "+M); //EKS[N]
		decMsg = aes.dec(SessionKey, M);
		System.out.println("Challenge content N2: "+decMsg);
	}
}
