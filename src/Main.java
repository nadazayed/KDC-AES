import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main 
{
	static Entity A;
	static Entity B;
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, UnsupportedEncodingException 
	{
		System.out.println("1. A→KDC: IDA || IDB || N1\n" + 
				"2. KDC→A: EKa[Ks || IDB || N1 || EKb[Ks||IDA] ]\n" + 
				"3. A→B: EKb[Ks||IDA]\n" + 
				"4. B→A: EKs[N2]\n" + 
				"5. A→B: EKs[f(N2)]\n");
		
		A = new Entity("A");
		A.generateNonce();
		System.out.println("Node A created successfully\n");
		
		B = new Entity("B");
		System.out.println("Node B created successfully\n");
		
		A.connectToKDC("B");
		System.out.println("\nChallenge-1- A to B");
		String challenge1 = A.challengeI("B");
		
		B.acceptChallengeI("A",challenge1);
		
		System.out.println("\nChallenge-2- B to A");
		String challenge2 = B.challengeII("A");
		A.acceptChallengeII("B", challenge2);
		
		System.out.println("\nChallenge-3- A to B");
		String challenge3 = A.challengeIII("B");
		B.acceptChallengeIII("A", challenge3);
	}
}
