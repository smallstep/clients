using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace smallstep_client.library
{
    public class CSR
    {
        private CertificateAttributes certificateAttributes;

        public CSR(CertificateAttributes certificateAttributes)
        {
            this.certificateAttributes = certificateAttributes;
        }
        public CSRData CreateCsr(ECDsa privateClientEcdsaKey)
        {
            CSRData csrData = new CSRData();



            //A client creates a certificate signing request.
            CertificateRequest request = new CertificateRequest(
                new X500DistinguishedName($"CN={certificateAttributes.CN}, O={certificateAttributes.O}, OU={certificateAttributes.OU}, L={certificateAttributes.L}, ST={certificateAttributes.S}, C={certificateAttributes.C}, E={certificateAttributes.E}"),
                privateClientEcdsaKey,
                HashAlgorithmName.SHA256);


            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName(certificateAttributes.CN);
            request.CertificateExtensions.Add(sanBuilder.Build());


            //Not a CA, a server certificate.
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            //request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
            //request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.8") }, false));

            byte[] derEncodedCsr = request.CreateSigningRequest();
            var csrSb = new StringBuilder();
            csrSb.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");
            csrSb.AppendLine(Convert.ToBase64String(derEncodedCsr));
            csrSb.AppendLine("-----END CERTIFICATE REQUEST-----");

            //Thus far OK, this csr seems to be working when using an online checker.
            csrData.Certificate = csrSb.ToString();

            byte[] derEncodedPrivateKey = privateClientEcdsaKey.ExportECPrivateKey();
            var pkSb = new StringBuilder();

            pkSb.AppendLine("-----BEGIN PRIVATE KEY-----");
            pkSb.AppendLine(Convert.ToBase64String(derEncodedPrivateKey));
            pkSb.AppendLine("-----END PRIVATE KEY-----");

            csrData.PrivateKey = pkSb.ToString();


            return csrData;
        }
    }
}
