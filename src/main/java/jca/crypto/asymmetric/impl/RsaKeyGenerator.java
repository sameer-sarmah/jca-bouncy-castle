package jca.crypto.asymmetric.impl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jca.crypto.KeyPairType;
import jca.crypto.asymmetric.api.IKeyPairGenerator;
import jca.util.TrustStoreUtil;


@Component("RsaKeyGenerator")
public class RsaKeyGenerator implements IKeyPairGenerator{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(RsaKeyGenerator.class);

	@Override
	public KeyPair generateKeyPair() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA","BC");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
			//privateKey will be of type org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey
			PrivateKey privateKey = keyPair.getPrivate();
			//publicKey will be of type  org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
			PublicKey publicKey = keyPair.getPublic();
			TrustStoreUtil.analysePrivateKey(privateKey);
			TrustStoreUtil.analysePublicKey(publicKey);
			LOGGER.info("RSA Private key and Public key generated");
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	@Override
	public KeyPairType getType() {
		return KeyPairType.RSA;
	}
}
