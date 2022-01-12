using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using RestSharp;
using smallstep_client.library;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace smallstep_client.app
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string jwk_filename = "jwk.json";

            string jwkFileContent = File.ReadAllText(jwk_filename);

            JsonWebKey key = JsonWebKeySet.Create(jwkFileContent)?.Keys?.FirstOrDefault();

            if (key != null)
            {
                string token;
                string csrContent;
                using (ECDsa privateClientEcdsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
                {
                    var attributes = new CertificateAttributes(CN: "A1242342.smallstep.com", O: "Smallstep Inc", OU: "Security", L: "Istanbul", S: "Istanbul", C: "TR", E: "ca@smallstep.com");

                    CSR csr = new CSR(attributes);
                    var cert = csr.CreateCsr(privateClientEcdsaKey);

                    csrContent = cert.Certificate;

                    var now = DateTime.UtcNow;
                    var handler = new JsonWebTokenHandler();

                    token = handler.CreateToken(new SecurityTokenDescriptor
                    {
                        Issuer = attributes.E,
                        Audience = "https://ca.paydustry.com/1.0/sign",
                        NotBefore = now,
                        Expires = now.AddMinutes(30),
                        IssuedAt = now,
                        Claims = new Dictionary<string, object> { { "sub", attributes.CN }, { "jti", Guid.NewGuid().ToString() }, { "sans", new string[] { attributes.CN } } },
                        SigningCredentials = new SigningCredentials(key, "ES256"),
                        AdditionalHeaderClaims = new Dictionary<string, object> { },
                    });
                }

                var restClient = new RestClient("https://192.168.3.53");
                restClient.RemoteCertificateValidationCallback +=
                        (sender, certificate, chain, sslPolicyErrors) => true;

                var healthRequest = new RestRequest("/health");

                var healthRes = restClient.Get<RestHealthStatus>(healthRequest);

                if (healthRes.Data.status.Equals("ok"))
                {
                    RestSignReqBody body = new RestSignReqBody();
                    body.csr = csrContent;
                    body.ott = token;

                    var signRequest = new RestRequest("/1.0/sign");
                    signRequest.Body = new RequestBody("application/json", "cert", JsonSerializer.Serialize(body));

                    var signRes = restClient.Post(signRequest);

                    var cert = JsonSerializer.Deserialize<RestSignResult>(signRes.Content);

                    Console.WriteLine($"Cert: \n{cert.crt}");

                }

                Console.ReadKey();
            }
        }
    }
}
