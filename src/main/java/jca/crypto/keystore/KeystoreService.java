package jca.crypto.keystore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

@Component
public class KeystoreService {
	
	public byte[] storeCertificate(char[] storePassword, X509Certificate trustedCert)
			throws GeneralSecurityException, IOException {
		KeyStore keyStore = createKeyStore("BCFKS");
		keyStore.setCertificateEntry("trustedca", trustedCert);
		return storeKeyStore(keyStore,storePassword);
	}

	public byte[] storeSecretKey(char[] storePassword, char[] keyPass, SecretKey secretKey)
			throws GeneralSecurityException, IOException {
		KeyStore keyStore = createKeyStore("BCFKS");
		keyStore.setKeyEntry("secretkey", secretKey, keyPass, null);
		return storeKeyStore(keyStore,storePassword);
	}

	public byte[] storePrivateKey(char[] storePassword, char[] keyPass, PrivateKey eeKey,
			X509Certificate[] eeCertChain) throws GeneralSecurityException, IOException {
		KeyStore keyStore = createKeyStore("BCFKS");
		keyStore.setKeyEntry("key", eeKey, keyPass, eeCertChain);
		return storeKeyStore(keyStore,storePassword);
	}
	
	private KeyStore createKeyStore(String keyStoreType) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, NoSuchProviderException {
		//Unlike PKCS12, the BCFKS format can store certificates, private keys, and some types of secret key.
		KeyStore keyStore = KeyStore.getInstance(keyStoreType, "BC");
		keyStore.load(null, null);
		return keyStore;
	}
	
	private byte[] storeKeyStore(KeyStore keyStore,char[] storePassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		var outputStream = new ByteArrayOutputStream();
		keyStore.store(outputStream, storePassword);
		return outputStream.toByteArray();
	}

}
