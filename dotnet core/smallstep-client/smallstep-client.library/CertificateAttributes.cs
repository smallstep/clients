using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace smallstep_client.library
{
    public class CertificateAttributes
    {
        public string CN { get; set; }
        public string O { get; set; }
        public string OU { get; set; }
        public string L { get; set; }
        public string S { get; set; }
        public string C { get; set; }
        public string E { get; set; }

        public CertificateAttributes()
        {

        }

        public CertificateAttributes(string CN, string O, string OU, string L, string S, string C, string E)
        {
            this.CN = CN;
            this.O = O;
            this.OU = OU;
            this.L = L;
            this.S = S;
            this.C = C;
            this.E = E;
        }
    }
}
