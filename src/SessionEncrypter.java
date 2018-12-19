import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.security.Key;
import java.io.OutputStream;

public class SessionEncrypter{
Key key;
Cipher cipher;

public SessionEncrypter(SessionKey key, byte[] decodedIv) throws Exception{
  this.key = key.getSecretKey();
  this.cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
  this.cipher.init(Cipher.ENCRYPT_MODE, this.key, new IvParameterSpec(decodedIv));
  }

public String encodeKey(){
  return Base64.getEncoder().encodeToString(this.key.getEncoded());
  }

public String encodeIV(){
return  Base64.getEncoder().encodeToString(cipher.getIV());
}

CipherOutputStream openCipherOutputStream(OutputStream output){
return new CipherOutputStream(output, this.cipher);
}

}
