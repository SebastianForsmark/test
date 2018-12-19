
import javax.crypto.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;


class HandshakeCrypto{

static byte[] encrypt(byte[] plaintext, Key key) throws Exception{
  Cipher cipher = Cipher.getInstance("RSA");
  cipher.init(Cipher.ENCRYPT_MODE, key);
  return cipher.doFinal(plaintext);
  }

static byte[] decrypt(byte[] ciphertext, Key key) throws Exception{
  Cipher cipher = Cipher.getInstance("RSA");
  cipher.init(Cipher.DECRYPT_MODE, key);
  return cipher.doFinal(ciphertext);
  }

static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws Exception{
  KeyFactory keyFactory = KeyFactory.getInstance("RSA");
  byte[] keyfileBytes = Files.readAllBytes(Paths.get(keyfile));
  PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyfileBytes);
  return keyFactory.generatePrivate(keySpec);
  }

  //Not used in current implementation.
  /*
  public static PublicKey getPublicKeyFromCertFile(String certfile) throws Exception{
    CertificateFactory certFact = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) certFact.generateCertificate(new FileInputStream (certfile));
    return cert.getPublicKey();
    */
}

