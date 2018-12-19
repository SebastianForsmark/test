import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.io.OutputStream;

class SessionEncrypter{
private Cipher cipher;

SessionEncrypter(SessionKey seshKey, byte[] decodedIv) throws Exception{
  Key secretKey = seshKey.getSecretKey();
  this.cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
  this.cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(decodedIv));
  }

  //Not used in current implementation.
  /*
public String encodeKey(){
  return Base64.getEncoder().encodeToString(this.key.getEncoded());
  }

public String encodeIV(){
return  Base64.getEncoder().encodeToString(cipher.getIV());
}
*/

CipherOutputStream openCipherOutputStream(OutputStream output){
return new CipherOutputStream(output, this.cipher);
}

}
