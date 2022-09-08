package jca.crypto.asymmetric.wrapping;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import jca.crypto.asymmetric.api.IKeyPairGenerator;
import jca.crypto.symmetric.api.ISymKeyGenerator;

@Component
public class AsymKeyWrapper {

	@Qualifier("AesKeyGenerator")
	@Autowired
	private ISymKeyGenerator aesKeyGenerators;

	@Qualifier("RsaKeyGenerator")
	@Autowired
	private IKeyPairGenerator rsaPairGenerator;

	public void wrapAsymmetricKey() throws GeneralSecurityException {
		SecretKey aesKey = aesKeyGenerators.generateSecretKey();
		KeyPair rsaKeyPair = rsaPairGenerator.generateKeyPair();
		PrivateKey privateKey = rsaKeyPair.getPrivate();
		PublicKey publicKey = rsaKeyPair.getPublic();
		String keyBase64Str = Base64.getEncoder().encodeToString(aesKey.getEncoded());
		byte[] wrappedKey = wrapKey(publicKey, aesKey);
		String wrappedKeyBase64Str = Base64.getEncoder().encodeToString(wrappedKey);
		System.out.println(wrappedKeyBase64Str);
		SecretKey aesKeyUnwrapped = (SecretKey) unwrapKey(privateKey, wrappedKey);
		String unwrapedKeyBase64Str = Base64.getEncoder().encodeToString(aesKeyUnwrapped.getEncoded());
		Assert.isTrue(unwrapedKeyBase64Str.equals(keyBase64Str), () -> "Unwraped value should be same");

	}

	public byte[] wrapKey(PublicKey rsaPublic, SecretKey secretKey) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding", "BC");
		cipher.init(Cipher.WRAP_MODE, rsaPublic);
		return cipher.wrap(secretKey);
	}

	public Key unwrapKey(PrivateKey rsaPrivate, byte[] wrappedKey) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding", "BC");
		cipher.init(Cipher.UNWRAP_MODE, rsaPrivate);
		return cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
	}

}
