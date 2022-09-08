package jca.crypto.asymmetric.api;

import java.security.KeyPair;

import jca.crypto.KeyPairType;


public interface IKeyPairGenerator {
	KeyPair generateKey();
	KeyPairType getType();
}
