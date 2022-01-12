using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace smallstep_client.library
{

    public class RestSignResult
    {
        public string crt { get; set; }
        public string ca { get; set; }
        public string[] certChain { get; set; }
        public TlsOptions tlsOptions { get; set; }
    }

    public class TlsOptions
    {
        public string[] cipherSuites { get; set; }
        public float minVersion { get; set; }
        public float maxVersion { get; set; }
        public bool renegotiation { get; set; }
    }

}
