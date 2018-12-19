import java.security.*;
import java.security.cert.*;
import java.io.FileInputStream;



public class VerifyCertificate{
private X509Certificate caCert;
private X509Certificate userCert;
private CertificateFactory certFact = CertificateFactory.getInstance("X.509");

  public VerifyCertificate(X509Certificate caCertificate, X509Certificate userCertificate) throws Exception{
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

  String printDN() throws Exception{
   return "CA: " + this.caCert.getSubjectDN().toString() +"\nUSER:" + this.userCert.getSubjectDN().toString();
  }

  public static PublicKey extractPublicKey(X509Certificate certificate) throws Exception{
    return certificate.getPublicKey();
  }
}
