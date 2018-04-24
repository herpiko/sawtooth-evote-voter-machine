const fs = require('fs');
const prompt = require('prompt');
const {createHash} = require('crypto')
const forge = require('node-forge');
const pki = forge.pki;
const base64 = require('js-base64').Base64;

const config = JSON.parse(fs.readFileSync('config.json', 'utf8'));
const candidates = JSON.parse(fs.readFileSync('candidates.json', 'utf8'));


// The machine's keypair, derived from TPS's keypair.
const certPem = fs.readFileSync('cert/cert.pem', 'utf8');
const cert = pki.certificateFromPem(certPem);
const keyPem = fs.readFileSync('cert/key.pem', 'utf8');
const key = pki.privateKeyFromPem(keyPem);

prompt.start();
var candidatesPrompt = 'Candidates : ';
for (var i in candidates) {
  candidatesPrompt += '\n - ' + candidates[i].name;
}
candidatesPrompt += '\nPlease pick by number';
const schema = {
  properties : {
    cert : {
      message : 'Cert path',
      required : true,
      default : 'cert/cert.pem'
    },
    key : {
      message : 'Key path',
      required : true,
      default : 'cert/key.pem'
    },
    vote : {
      message : candidatesPrompt,
      required : true,
      default : 2
    },
     
  }
}
candidatesPrompt += '\nPlease vote (enter number)';
prompt.get(schema, (err, result) => {

  const vote = parseInt(result.vote);
  if (vote < 0 || vote > candidates.length) {
    console.log(vote + ' is not a valid candidate');
    process.exit(1);
  }

  const voterCertPem = fs.readFileSync(result.cert, 'utf8');
  const voterCert = pki.certificateFromPem(certPem);
  const voterKeyPem = fs.readFileSync(result.key, 'utf8');
  const voterKey = pki.privateKeyFromPem(keyPem);
 
  /*
  The bailout consists of :
    - Last 8 character of sha256 hash of region
    - Last 8 character of sha256 hash of tpsId
    - machineId
    - Vote
    - Signature of previous value string (ex : a2cc25e1-b7875b4b-2-1), signed by voterMachine's key
    - Separated by minus sign ('-')
  */

  let bailout = '';
  bailout += createHash('sha256').update(config.region).digest('hex').substr(-8);
  bailout += '-';
  bailout += createHash('sha256').update(config.tpsId).digest('hex').substr(-8);
  bailout += '-';
  bailout += config.machineId;
  bailout += '-';
  bailout += vote;

  var p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(bailout);
  p7.addCertificate(cert);
  p7.addSigner({
    key: key,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [{
      type: forge.pki.oids.contentType,
      value: forge.pki.oids.data,
    },
    {
      type: forge.pki.oids.messageDigest
    },
    {
      type: forge.pki.oids.signingTime,
      value: new Date()
    }
    ]
  });
  p7.sign();
  var pem = forge.pkcs7.messageToPem(p7).replace(/\r?\n|\r/g, '').split('-----')[2];
  // TODO this signature is too large for QRCode encoding. 
  // Find a way to shrink it (and still be able to verify)
  bailout += '-';
  bailout += pem

  var txName = base64.encode(voterCert.subject.getField('CN').value);
  var txValue;
  p7 = forge.pkcs7.createEnvelopedData();
  p7.addRecipient(voterCert);
  p7.content = forge.util.createBuffer(vote);
  p7.encrypt();
  txValue = forge.pkcs7.messageToPem(p7).replace(/\r?\n|\r/g, '').split('-----')[2];
  var tx = { name : txName, value : txValue };
  // TODO submit to DPT ledger. DPT tp is not ready yet.
  console.log(tx);

  let path = 'bailouts/bailout-' + bailout.replace(/\-/g,'').replace(/\+/g,'').replace(/\//g,'').substr(-16) + '.txt';
  fs.writeFile(path, bailout + '\n', function(err){
    if (err) {
      console.log('Failed to print the bailout paper : ' + err);
      process.exit(1);
    }
    console.log('\nThe bailout paper has been printed out (' + path + '). Please take it to the vote box.');
  });
});
