package jca.app;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import jca.crypto.KeyPairType;
import jca.crypto.KeyType;
import jca.crypto.asymmetric.api.IKeyGenerator;
import jca.crypto.asymmetric.decryption.AsymDecrypter;
import jca.crypto.asymmetric.encryption.AsymEncrypter;
import jca.crypto.asymmetric.signature.SignatureService;
import jca.crypto.digest.api.IHashGenerator;
import jca.crypto.symmetric.api.ISymKeyGenerator;
import jca.crypto.symmetric.decryption.SymDecrypter;
import jca.crypto.symmetric.encryption.SymEncrypter;

@Component
public class Runner implements ApplicationRunner {
	
	@Autowired
	private List<IKeyGenerator> asymKeyGenerators;
	
	@Autowired
	private List<ISymKeyGenerator> symKeyGenerators;
	
	@Autowired
	private IHashGenerator hashGenerator;
	
	@Autowired
	private SymEncrypter symEncrypter;
	
	@Autowired
	private SymDecrypter symDecrypter;
	
	@Autowired
	private AsymEncrypter asymEncrypter;
	
	@Autowired
	private AsymDecrypter asymDecrypter;
	
	@Autowired
	private SignatureService signatureService;

	@Override
	public void run(ApplicationArguments args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		//symEncryptDecrypt() ;
		//asymEncryptDecrypt();
		//generateDigest();
		signature();
	}
	
	private void signature() throws GeneralSecurityException {
		Optional<IKeyGenerator> generatorOptional = asymKeyGenerators.stream()
				.filter(keyGenerator -> keyGenerator.getType().equals(KeyPairType.RSA))
				.findAny();
		if(generatorOptional.isPresent()) {
			KeyPair keyPair = generatorOptional.get().generateKey();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			String input = "RSA is an asymmetric cryptographic algorithm.";
			String asymAlgorithm = "RSA/ECB/PKCS1Padding";
			byte[]  signedContent = signatureService.generateSignature(privateKey, input.getBytes());
			boolean isVerified = signatureService.verifySignature(publicKey, input.getBytes(), signedContent);
			System.out.println("Is content verified="+isVerified);
		}
	}
		
	private void asymEncryptDecrypt() {
		Optional<IKeyGenerator> generatorOptional = asymKeyGenerators.stream()
				.filter(keyGenerator -> keyGenerator.getType().equals(KeyPairType.RSA))
				.findAny();
		if(generatorOptional.isPresent()) {
			KeyPair keyPair = generatorOptional.get().generateKey();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			IvParameterSpec iv = generateIv();
			String input = "RSA is an asymmetric cryptographic algorithm.";
			String asymAlgorithm = "RSA/ECB/PKCS1Padding";
			String symAlgorithm = "AES/CBC/PKCS5Padding";
			SecretKey secretKey = getSymmetricKey();
			try {
				String encryptedContentUsingSymKey = symEncrypter.encrypt(symAlgorithm, input, secretKey, iv);
				String encryptedContent = asymEncrypter.encrypt(asymAlgorithm, encryptedContentUsingSymKey, publicKey);
				System.out.println(encryptedContent);
				String decryptedContent =  asymDecrypter.decrypt(asymAlgorithm, encryptedContent, privateKey);
				System.out.println(decryptedContent);
				Assert.isTrue(decryptedContent.equals(encryptedContentUsingSymKey),()->"Input message and decrypted message should be same ");
			} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
					| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	private void symEncryptDecrypt() {
		SecretKey secretKey = getSymmetricKey();
		IvParameterSpec iv = generateIv();
		String input = "The symmetric-key block cipher plays an important role in data encryption. It means that the same key is used for both encryption and decryption. The Advanced Encryption Standard (AES) is a widely used symmetric-key encryption algorithm.";
		String algorithm = "AES/CBC/PKCS5Padding";
		try {
			String encryptedContent = symEncrypter.encrypt(algorithm, input, secretKey, iv);
			System.out.println(encryptedContent);
			String decryptedContent =  symDecrypter.decrypt(algorithm, encryptedContent, secretKey, iv);
			System.out.println(decryptedContent);
			Assert.isTrue(decryptedContent.equals(input),()->"Input message and decrypted message should be same ");
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private SecretKey getSymmetricKey() {
		Optional<ISymKeyGenerator> generatorOptional = symKeyGenerators.stream()
				.filter(keyGenerator -> keyGenerator.getType().equals(KeyType.AES))
				.findAny();
		if(generatorOptional.isPresent()) {
			return generatorOptional.get().generateSecretKey();
		}
		return null;
	}
	

	
	private void generateDigest() {
		String input = "The symmetric-key block cipher plays an important role in data encryption. It means that the same key is used for both encryption and decryption. The Advanced Encryption Standard (AES) is a widely used symmetric-key encryption algorithm.";		
		MessageDigest digest = hashGenerator.generateMessageDigest();
		byte[] hashedContent = digest.digest(input.getBytes());
		String hashedBase64Str = Base64.getEncoder().encodeToString(hashedContent);
		System.out.println(hashedBase64Str);
		hashedContent = digest.digest(input.getBytes());
		String rehashedBase64Str = Base64.getEncoder().encodeToString(hashedContent);
		Assert.isTrue(rehashedBase64Str.equals(hashedBase64Str),()->"Hashed value should be same");
	}
	
	public  IvParameterSpec generateIv() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return new IvParameterSpec(iv);
	}
	
}
