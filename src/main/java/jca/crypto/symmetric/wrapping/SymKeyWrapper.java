package jca.crypto.symmetric.wrapping;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import jca.crypto.symmetric.api.ISymKeyGenerator;

@Component
public class SymKeyWrapper {

	@Qualifier("AesKeyGenerator")
	@Autowired
	private ISymKeyGenerator aesKeyGenerators;

	@Qualifier("DesKeyGenerator")
	@Autowired
	private ISymKeyGenerator desKeyGenerators;

	public void wrapSymmetricKey() throws GeneralSecurityException {
		SecretKey aesKey = aesKeyGenerators.generateSecretKey();
		SecretKey desKey = desKeyGenerators.generateSecretKey();
		String keyBase64Str = Base64.getEncoder().encodeToString(desKey.getEncoded());
		byte[] wrappedKey = wrapKey(aesKey, desKey);
		String wrappedKeyBase64Str = Base64.getEncoder().encodeToString(wrappedKey);
		System.out.println(wrappedKeyBase64Str);
		SecretKey desKeyUnwrapped = (SecretKey) unwrapKey(aesKey, wrappedKey);
		String unwrapedKeyBase64Str = Base64.getEncoder().encodeToString(desKeyUnwrapped.getEncoded());
		Assert.isTrue(unwrapedKeyBase64Str.equals(keyBase64Str),()->"Unwraped value should be same");
		
	}

	public byte[] wrapKey(SecretKey key, SecretKey keyToWrap) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AESKW", "BC");
		cipher.init(Cipher.WRAP_MODE, key);
		return cipher.wrap(keyToWrap);
	}

	public Key unwrapKey(SecretKey key, byte[] wrappedKey) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AESKW", "BC");
		cipher.init(Cipher.UNWRAP_MODE, key);
		return cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
	}

}
