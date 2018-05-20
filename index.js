const fs = require('fs');
const prompt = require('prompt');
const {createHash} = require('crypto')
const {spawnSync} = require('child_process');
const forge = require('node-forge');
const pki = forge.pki;
const base64 = require('js-base64').Base64;
const voteSubmitter = require('./submitter/vote');

const config = JSON.parse(fs.readFileSync('config.json', 'utf8'));
const candidates = JSON.parse(fs.readFileSync('candidates.json', 'utf8'));

// TPS key pair
const certPem = fs.readFileSync('certs/tps/tps_527105_001.pem', 'utf8');
const tpsCert = pki.certificateFromPem(certPem);
const keyPem = fs.readFileSync('certs/tps/tps_527105_001.plain.key', 'utf8');
const tpsKey = pki.privateKeyFromPem(keyPem);

// Kunci Suara
const kunciSuaraPem = fs.readFileSync('certs/kpu-tallyer/kunci_suara.pem', 'utf8');
const kunciSuara = pki.certificateFromPem(kunciSuaraPem);

prompt.start();
const schema = {
  properties : {
    cert : {
      message : 'Cert path',
      required : true,
      default : 'certs/dpt/herpiko_52710501019120001.pem'
    },
    key : {
      message : 'Key path',
      required : true,
      default : 'certs/dpt/herpiko_52710501019120001.plain.key'
    },
  }
}

prompt.get(schema, (err, result) => {
  var UID;
  const voterCertPem = fs.readFileSync(result.cert, 'utf8');
  const voterCert = pki.certificateFromPem(voterCertPem);
  const voterKeyPem = fs.readFileSync(result.key, 'utf8');
  const voterKey = pki.privateKeyFromPem(voterKeyPem);

  console.log("\nVOTER IDENTITY on " + result.cert);
  console.log("=====================================");
  for (var i in voterCert.subject.attributes) {
    console.log((voterCert.subject.attributes[i].name || voterCert.subject.attributes[i].type) + ' : ' + voterCert.subject.attributes[i].value);
    if (voterCert.subject.attributes[i].type === '0.9.2342.19200300.100.1.1') {
      UID = voterCert.subject.attributes[i].value;
    }
  }
  console.log("=====================================\n");

  // Verify eKTP cert
  const rootCA = pki.certificateFromPem(fs.readFileSync('certs/ca/KominfoRootCA.pem', 'utf8'));
  const dukcapilCA = pki.certificateFromPem(fs.readFileSync('certs/ca/DukcapilIntermediateCA.pem', 'utf8'));
  console.log('Verifying cert against CA...');
  try {
    const verified = dukcapilCA.verify(voterCert)
    console.log('- Verified');
  } catch (e) {
    console.log('\nError : eKTP is not verified');
    return;
  }

  // Verify against CRL
  console.log('Verifying cert against CRL...');
  let spawned = spawnSync('openssl', ['verify',  '-crl_check', '-CAfile', 'certs/ca/DukcapilIntermediateCA.crl-chain.pem', result.cert]);
  let crlCheckResult = spawned.stdout.toString().indexOf('OK') > -1
  console.log(crlCheckResult ? '- Verified\n' : '- Not verified / revoked');
  if (!crlCheckResult) return;

  // TODO Check against DPT
  //

  var candidatesPrompt = '\nCandidates : ';
  for (var i in candidates) {
    candidatesPrompt += '\n - ' + candidates[i].name;
  }
  candidatesPrompt += '\nPlease pick by number';
  const voteSchema = {
    properties : {
      vote : {
        message : candidatesPrompt,
        required : true,
        default : 2
      },
    }
  }
  candidatesPrompt += '\n\nPlease vote (enter number)';
  prompt.get(voteSchema, (err, result) => {

    const vote = parseInt(result.vote);
    if (vote < 0 || vote > candidates.length) {
      console.log(vote + ' is not a valid candidate');
      process.exit(1);
    }
    let u = (new Date()).valueOf();
    u = createHash('sha256').update(u.toString()).digest('hex');
    var idv = createHash('sha256').update(u + UID).digest('hex');
    console.log(`\nYour idv : ${idv.toUpperCase()}`);

    p7 = forge.pkcs7.createEnvelopedData();
    p7.addRecipient(kunciSuara);
    p7.content = forge.util.createBuffer(vote);
    p7.encrypt();
    let bailout = forge.pkcs7.messageToPem(p7).replace(/\r?\n|\r/g, '').split('-----')[2];

    var p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(bailout);
    p7.addCertificate(tpsCert);
    p7.addSigner({
      key: tpsKey,
      certificate: tpsCert,
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
    let payload = {};
    payload[idv] = pem;
    console.log('\nPayload : ' + JSON.stringify(payload));
    voteSubmitter(process.argv[2], idv.substr(0, 20), pem)
    .then((result) => {
      console.log(result);
    })
    .catch((err) => {
      console.log(err);
    })

  });
});
