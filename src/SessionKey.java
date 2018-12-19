//Imports
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Arrays;
import java.security.Key;
import java.security.SecureRandom;


public class SessionKey{
private KeyGenerator keyGen;
private SecureRandom secRandom = new SecureRandom();
private SecretKey key;

/*
public static void main(String args[]) throws Exception{
  SessionKey key1 = new SessionKey(128);
  SessionKey key2 = new SessionKey(key1.encodeKey());
  if (key1.getSecretKey().equals(key2.getSecretKey())) {
    System.out.println("Pass");
    }
  else {
    System.out.println("Fail");
    }
  }
*/

public SessionKey(int keyLength)throws Exception{
  this.keyGen = KeyGenerator.getInstance("AES");
  keyGen.init(keyLength, this.secRandom);
  this.key = keyGen.generateKey();
  }

public SessionKey(byte[] encodedKey){
  byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
  this.key = new SecretKeySpec(decodedKey, "AES");
  }

public Key getSecretKey(){
  return this.key;
  }

public String encodeKey(){
  return Base64.getEncoder().encodeToString(this.key.getEncoded());
  }
}
