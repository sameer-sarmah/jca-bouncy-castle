package jca.crypto.symmetric.encryption;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

@Component
public class PasswordBasedEncryption {
	
	public SecretKey makePbeKey() throws GeneralSecurityException {
		char[] password = "Qwerty@1234".toCharArray();
		SecretKeyFactory keyFact = SecretKeyFactory.getInstance("HmacSHA384", "BC");
		byte[] salt = getSalt();
		int interation = 256;
		int keyLength = 256;
		var key = new PBEKeySpec(password, salt, interation, keyLength);
		SecretKey hmacKey = keyFact.generateSecret(key);
		System.out.println(Base64.getEncoder().encodeToString(hmacKey.getEncoded()));
		return new SecretKeySpec(hmacKey.getEncoded(), "AES");
	}

	private byte[] getSalt() {
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[16];
		random.nextBytes(salt);
		return salt;
	}

}
