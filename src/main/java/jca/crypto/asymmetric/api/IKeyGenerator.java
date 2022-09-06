package jca.crypto.asymmetric.api;

import java.security.KeyPair;

import jca.crypto.KeyPairType;


public interface IKeyGenerator {
	KeyPair generateKey();
	KeyPairType getType();
}
