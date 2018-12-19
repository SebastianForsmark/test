//Imports
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.security.Key;
import java.security.SecureRandom;


class SessionKey{
private SecretKey key;

SessionKey(int keyLength)throws Exception{
  KeyGenerator keyGen = KeyGenerator.getInstance("AES");
  keyGen.init(keyLength, new SecureRandom());
  this.key = keyGen.generateKey();
  }

SessionKey(byte[] encodedKey){
  byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
  this.key = new SecretKeySpec(decodedKey, "AES");
  }

Key getSecretKey(){
  return this.key;
  }

String encodeKey(){
  return Base64.getEncoder().encodeToString(this.key.getEncoded());
  }
}
