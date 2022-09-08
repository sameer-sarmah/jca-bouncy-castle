package jca.util;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class TrustStoreUtil {
	
	private static final Logger LOG = LoggerFactory.getLogger(TrustStoreUtil.class);
	
	private static final String EQUAL = "=";
	private static final String COMMA = ",";

	
	public static void analysePublicKey(PublicKey publicKey) {
		StringBuilder builder = new StringBuilder("PublicKey metadata.");
		analyseKey(publicKey, builder);
	}
	
	private static void analyseKey(Key key,StringBuilder builder) {
		 builder.append("Algorithm").append(EQUAL).append(key.getAlgorithm())
				//.append("Key").append(EQUAL).append(new String(key.getEncoded(),Charset.defaultCharset()))
				.append("Format").append(EQUAL).append(key.getFormat());
		 LOG.info(builder.toString());
	}
	
	public static void analysePrivateKey(PrivateKey privateKey) {
		StringBuilder builder = new StringBuilder("PrivateKey metadata.");
		analyseKey(privateKey, builder);
	}
		
	public static List<X509Certificate>  analyseCertificate(KeyStore keyStore,List<String> publicKeys) {
		List<X509Certificate> certificates = null;
		try {
			System.out.println(String.format("Size of keystore: %s, type of keystore: %s ",keyStore.size(),keyStore.getType()));
			certificates = publicKeys
				.stream()
				.map((publicKey) ->{
				try {
					X509Certificate clientCertificate = (X509Certificate) keyStore.getCertificate(publicKey);
					return  clientCertificate;
				}  catch (KeyStoreException e) {
					System.err.println(e.getMessage());
				}
				return null;	
			})
				.filter(clientCertificate -> Objects.nonNull(clientCertificate))
				.collect(Collectors.toList());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return certificates;
	}
	

	
}
