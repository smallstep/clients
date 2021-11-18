import fs from 'fs'
import * as jose from 'jose'
import got from 'got'
import * as x509 from '@peculiar/x509'
import { webcrypto } from 'crypto'

x509.cryptoProvider.set(webcrypto);

let StepClient = class {
	async init(caURL, caFingerprint) {
		this.caURL = caURL
		this.caFingerprint = caFingerprint
		this.caRootPEM = await this.fetchRootPEM()
	}

	async health() {
	  try {
		  const body = await got(new URL('/health', this.caURL),
		  	  { https: { certificateAuthority: this.caRootPEM } }
		  ).json()
		  return body.status
	  } catch (error) {
		  console.error(error)
	  }
	}

    get signURL() {
		return new URL('/1.0/sign', this.caURL)
	}

	async sign(csr, token) {
	  try {
		  const body = await got.post(this.signURL,
		  	  { https: { certificateAuthority: this.caRootPEM },
				json: { csr: csr, ott: token }
			  }
		  ).json()
		  return body
	  } catch (error) {
		  console.error(error.request)
	  }
	}

	async fetchRootPEM() {
	  try {
		  const body = await got(new URL('/root/' + this.caFingerprint, this.caURL),
		  	  { https: { rejectUnauthorized: false }}
		  ).json();
		  return body.ca
	  } catch (error) {
		  console.error(error);
	  }
	}
}

async function generate_csr(cn, dnsSANs) {
	const alg = {
		  name: "ECDSA",
		  namedCurve: "P-256",
		  hash: "SHA-256",
	}
	const keys = await webcrypto.subtle.generateKey(alg, false, ["sign", "verify"])
	const csr = await x509.Pkcs10CertificateRequestGenerator.create({
		  name: 'CN='.concat(cn),
		  keys,
		  signingAlgorithm: alg,
		  extensions: [
			new x509.SubjectAlternativeNameExtension({ dns: dnsSANs }, false),
			new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
			new x509.ExtendedKeyUsageExtension([
				'1.3.6.1.5.5.7.3.1', // server auth
				'1.3.6.1.5.5.7.3.2'  // client auth
			], false),
		  ]
	});
	return csr
}

async function generate_jwt(cn, dnsSANs, audience, issuer, jwkFilename) {
	// make the jwk
	const jwkJSON = await JSON.parse(fs.readFileSync(jwkFilename).toString())
	const privateKey = await jose.importJWK(jwkJSON)
	const kid = jwkJSON.kid

	const jwt = await new jose.SignJWT({ 
		sans: dnsSANs,
		sub: cn,
	})
	  .setProtectedHeader({ alg: 'ES256', kid: kid })
	  .setIssuedAt()
	  .setIssuer(provisionerName)
	  .setAudience(audience)
	  .setNotBefore('0s')
	  .setExpirationTime('5m')
	  .sign(privateKey)
	// console.log(jwt)
	return jwt
}

// import yargs from 'yargs'
// import { hideBin } from 'yargs/helpers'
// 
// yargs(hideBin(process.argv))
//   .command('signer [CA URL] [CA Fingerprint] [provisioner name] [JWK PEM]', 'fetch the contents of the URL')
//   .demandCommand(3)
//   .parse()

let caUrl = 'https://ca:4443'
let caFingerprint = 'c8de28e620ec4367f734a0c405d92d7350dbec351cec3e4f6a6d1fc9512387aa'

// this is the JWK private key from the CA's JWK provisioner.
const jwkFilename = 'jwk.json'

// the label of the JWK provisioner in the CA
const provisionerName = 'jwktest'

// the common name and DNS sans for the certificate
const cn = 'localhost'
const dnsSANs = ['localhost']

let step = new StepClient()
await step.init(caUrl, caFingerprint)

const jwt = await generate_jwt(cn, dnsSANs, step.signURL, provisionerName, jwkFilename)
const csr = await generate_csr(cn, dnsSANs)
const certResponse = await step.sign(csr.toString("pem"), jwt)
console.log(certResponse.crt)

