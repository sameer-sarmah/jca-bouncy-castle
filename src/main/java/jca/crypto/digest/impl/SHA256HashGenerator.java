package jca.crypto.digest.impl;

import java.security.MessageDigest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jca.crypto.digest.api.IHashGenerator;


@Component
public class SHA256HashGenerator implements IHashGenerator{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(SHA256HashGenerator.class);

	@Override
	public MessageDigest generateMessageDigest() {
		MessageDigest digest = null;
		try {
			digest = MessageDigest.getInstance("SHA-256","BC");	
			LOGGER.info("SHA256 hash generated");
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return digest;
	}
}
