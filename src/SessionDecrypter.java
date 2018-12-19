import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.security.Key;
import java.io.InputStream;

public class SessionDecrypter{
Cipher cipher;

public SessionDecrypter(SessionKey key, IvParameterSpec iv) throws Exception{
  this.cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
  this.cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(),iv);
  }

CipherInputStream openCipherInputStream(InputStream input){
  return new CipherInputStream(input, this.cipher);
  }
}
