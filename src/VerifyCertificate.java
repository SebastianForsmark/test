import java.security.cert.*;

class VerifyCertificate{
private X509Certificate caCert;
private X509Certificate userCert;

  VerifyCertificate(X509Certificate caCertificate, X509Certificate userCertificate){
    this.caCert = caCertificate;
    this.userCert = userCertificate;
  }

  void testValidity() throws Exception{
   this.caCert.checkValidity();
   this.caCert.verify(this.caCert.getPublicKey());
   this.userCert.checkValidity();
   this.userCert.verify(this.caCert.getPublicKey());
      System.out.println("Certificates validated!");
  }

  //Not used in current implementation
  /*
  String printDN() throws Exception{
   return "CA: " + this.caCert.getSubjectDN().toString() +"\nUSER:" + this.userCert.getSubjectDN().toString();
  }
  public static PublicKey extractPublicKey(X509Certificate certificate) throws Exception{
    return certificate.getPublicKey();
  }
  */
}
