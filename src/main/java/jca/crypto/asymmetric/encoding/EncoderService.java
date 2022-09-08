package jca.crypto.asymmetric.encoding;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import jca.util.TrustStoreUtil;

@Component
public class EncoderService {

	@Value("${key-store-file}")
	private String keyStoreFile;
	@Value("${server.ssl.key-store-password}")
	private String keyStorePwd;
	@Value("${server.ssl.key-password}")
	private String keyPwd;
	@Value("${server.ssl.key-store-type}")
	private String keyStoreType;

	public byte[] encodePrivate(PrivateKey privateKey) {
		return privateKey.getEncoded();
	}

	public PrivateKey producePrivateKey(byte[] encoding) throws GeneralSecurityException {
		KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
		return keyFact.generatePrivate(new PKCS8EncodedKeySpec(encoding));
	}

	public byte[] encodePublic(PublicKey publicKey) {
		return publicKey.getEncoded();
	}

	public PublicKey producePublicKey(byte[] encoding) throws GeneralSecurityException {
		KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
		return keyFact.generatePublic(new X509EncodedKeySpec(encoding));
	}

	public String writeCertificate(X509Certificate certificate) throws IOException {
		StringWriter sWrt = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter(sWrt);
		pemWriter.writeObject(certificate);
		pemWriter.close();
		return sWrt.toString();
	}

	public X509Certificate readCertificate(String pemEncoding) throws IOException, CertificateException {
		PEMParser parser = new PEMParser(new StringReader(pemEncoding));
		X509CertificateHolder certHolder = (X509CertificateHolder) parser.readObject();
		return new JcaX509CertificateConverter().getCertificate(certHolder);
	}

	public String writePrivateKey(PrivateKey privateKey) throws IOException {
		StringWriter sWrt = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter(sWrt);
		pemWriter.writeObject(privateKey);
		pemWriter.close();
		return sWrt.toString();
	}

	public PrivateKey readPrivateKey(String pemEncoding) throws IOException, CertificateException {
		PEMParser parser = new PEMParser(new StringReader(pemEncoding));
		PEMKeyPair pemKeyPair = (PEMKeyPair) parser.readObject();
		return new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
	}

	public static String writeEncryptedKey(char[] passwd, PrivateKey privateKey)
			throws IOException, OperatorCreationException {
		StringWriter sWrt = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter(sWrt);
		PKCS8EncryptedPrivateKeyInfoBuilder pkcs8Builder = new JcaPKCS8EncryptedPrivateKeyInfoBuilder(privateKey);
		pemWriter.writeObject(
				pkcs8Builder.build(new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
						.setProvider("BC").build(passwd)));
		pemWriter.close();
		return sWrt.toString();
	}

	public static PrivateKey readEncryptedKey(char[] password, String pemEncoding)
			throws IOException, OperatorCreationException, PKCSException {
		PEMParser parser = new PEMParser(new StringReader(pemEncoding));
		PKCS8EncryptedPrivateKeyInfo encPrivKeyInfo = (PKCS8EncryptedPrivateKeyInfo) parser.readObject();
		InputDecryptorProvider pkcs8Prov = new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BCFIPS")
				.build(password);
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BCFIPS");
		return converter.getPrivateKey(encPrivKeyInfo.decryptPrivateKeyInfo(pkcs8Prov));
	}

	public void loadKeystore() throws Exception {
		KeyStore keyStore = readKeyStore(keyStoreFile, keyStorePwd, keyStoreType);
		List<X509Certificate> certificates = TrustStoreUtil.analyseCertificate(keyStore,
				List.of("mtls-client", "mtls-server"));
		certificates.stream().map(certificate -> {
			try {
				String pemCert = writeCertificate(certificate);
				System.out.println(pemCert);
				return pemCert;
			} catch (IOException e) {
				System.err.println(e.getMessage());
			}
			return "";
		}).forEach(pemCert -> {
			try {
				X509Certificate certificate = readCertificate(pemCert);
				Assert.isTrue(Objects.nonNull(certificate),
						() -> "Parsed certificate from encoded PEM string should not be null");
			} catch (CertificateException | IOException e) {
				System.err.println(e.getMessage());
			}
		});
		PrivateKey privateKey = (PrivateKey) keyStore.getKey("mtls-client", keyStorePwd.toCharArray());
		String pemPrivateKey = writePrivateKey(privateKey);
		System.out.println(pemPrivateKey);
		
		String encryptedPemPrivateKey = writeEncryptedKey(keyStorePwd.toCharArray(),privateKey);
		System.out.println(encryptedPemPrivateKey);

	}

	private KeyStore readKeyStore(String keystoreFile, String keystorePwd, String keyStoreType) throws Exception {
		try (InputStream keyStoreStream = this.getClass().getClassLoader().getSystemResourceAsStream(keystoreFile)) {
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(keyStoreStream, keystorePwd.toCharArray());
			return keyStore;
		}
	}

}
