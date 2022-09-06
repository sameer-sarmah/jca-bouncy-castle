package jca.crypto.symmetric.impl;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jca.crypto.KeyType;
import jca.crypto.symmetric.api.ISymKeyGenerator;

@Component
public class AesKeyGenerator implements ISymKeyGenerator{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(AesKeyGenerator.class);

	@Override
	public SecretKey generateSecretKey() {
		SecretKey secretKey;
		try {
			//instance of javax.crypto.spec.SecretKeySpec
			secretKey = KeyGenerator.getInstance("AES","BC").generateKey();			
			LOGGER.info("AES key generated");
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return secretKey;
	}

	@Override
	public KeyType getType() {
		return KeyType.AES;
	}

}
