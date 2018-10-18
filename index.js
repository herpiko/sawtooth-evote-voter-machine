const fs = require('fs');
const prompt = require('prompt');
const {createHash} = require('crypto')
const {spawnSync} = require('child_process');
const forge = require('node-forge');
const cbor = require('cbor')
const pbkdf2 = require('pbkdf2');
const request = require('request');
const pki = forge.pki;
const base64 = require('js-base64').Base64;
const voteSubmitter = require('../sawtooth-evote-submitter/vote');
const targetDPTHost = process.argv[2] || '172.30.0.111:21311'
const targetVoteHost = process.argv[2] || '172.30.0.211:22311'

const config = JSON.parse(fs.readFileSync('config.json', 'utf8'));

// TPS key pair
const certPem = fs.readFileSync('../sawtooth-evote-ejbca/KPU_Machines/TPS/527105_001/tps_527105_001.pem', 'utf8');
const tpsCert = pki.certificateFromPem(certPem);
const keyPem = fs.readFileSync('../sawtooth-evote-ejbca/KPU_Machines/TPS/527105_001/tps_527105_001.plain.key', 'utf8');
const tpsKey = pki.privateKeyFromPem(keyPem);

// Kunci Suara
const kunciSuaraPem = fs.readFileSync('../sawtooth-evote-ejbca/KPU_Machines/KunciSuara/kunci_suara.pem', 'utf8');
const kunciSuara = pki.certificateFromPem(kunciSuaraPem);

prompt.start();
const schema = {
  properties : {
    cert : {
      message : 'Cert path',
      required : true,
      default : '../sawtooth-evote-ejbca/Dukcapil_DPT/52710501019120001_herpiko_dwi_aguno.pem'
    },
    key : {
      message : 'Key path',
      required : true,
      default : '../sawtooth-evote-ejbca/Dukcapil_DPT/52710501019120001_herpiko_dwi_aguno.plain.key'
    },
    kValue : {
      message : 'k Value',
      required : true,
    },
  }
}

prompt.get(schema, (err, result) => {
  var commonName;
  var kValue = result.kValue;
  const voterCertPem = fs.readFileSync(result.cert, 'utf8');
  const voterCert = pki.certificateFromPem(voterCertPem);
  const voterKeyPem = fs.readFileSync(result.key, 'utf8');
  const voterKey = pki.privateKeyFromPem(voterKeyPem);

  console.log("\nVOTER IDENTITY on " + result.cert);
  console.log("=====================================");
  for (var i in voterCert.subject.attributes) {
    console.log((voterCert.subject.attributes[i].name || voterCert.subject.attributes[i].type) + ' : ' + voterCert.subject.attributes[i].value);
    if (voterCert.subject.attributes[i].name === 'commonName') {
      commonName = voterCert.subject.attributes[i].value;
    }
  }
  console.log("=====================================\n");
  if (!commonName) {
    console.log('Invalid commonName, please inspect the cert.');
    return;
  }

  // Verify eKTP cert
  const rootCA = pki.certificateFromPem(fs.readFileSync('../sawtooth-evote-ejbca/CA/KominfoRootCA.pem', 'utf8'));
  const dukcapilCA = pki.certificateFromPem(fs.readFileSync('../sawtooth-evote-ejbca/CA/DukcapilIntermediateCA.pem', 'utf8'));
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
  let spawned = spawnSync('openssl', ['verify',  '-crl_check', '-CAfile', '../sawtooth-evote-ejbca/CA/DukcapilIntermediateCA-crl-chain.pem', result.cert]);
  let crlCheckResult = spawned.stdout.toString().indexOf('OK') > -1
  console.log(crlCheckResult ? '- Verified\n' : '- Not verified / revoked');
  if (!crlCheckResult) {
    return;
  }

  // Check the voter id against local DPT ledger. The state should be ready, otherwise, abort.
  let familyName = 'localDPT';
  let nameHash = createHash('sha256').update(commonName).digest('hex')
  let payloadNameHash = createHash('sha512').update(nameHash).digest('hex');
  let familyNameHash = createHash('sha512').update(familyName).digest('hex');
  let stateId = familyNameHash.substr(0, 6) + payloadNameHash.substr(-64);
  request.get('http://' + targetDPTHost + '/state/' + stateId, (err, res) => {
    let buf = Buffer.from(JSON.parse(res.body).data, 'base64');
    let decoded = cbor.decode(buf);
    let keys = Object.keys(decoded);
    if (decoded[keys[0]] !== 'ready') {
      console.log('VoterID is NOT READY to vote. Aborted.');
      return;
    }

    // Fetch candidats from local DPT ledger
    let familyName = 'candidates';
    let payloadNameHash = createHash('sha512').update('candidates').digest('hex');
    let familyNameHash = createHash('sha512').update(familyName).digest('hex');
    let stateId = familyNameHash.substr(0, 6) + payloadNameHash.substr(-64);
    request.get('http://' + targetDPTHost + '/state/' + stateId, (err, res) => {
      let buf = Buffer.from(JSON.parse(res.body).data, 'base64');
      let decoded = cbor.decode(buf);
      let candidates = JSON.parse(base64.decode(decoded.candidates));
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
    
        const idv = pbkdf2.pbkdf2Sync(kValue, commonName, 1, 32, 'sha512').toString('base64') + kValue.substr(45);
        console.log(`\nYour k : ${kValue}`);
        console.log(`\nYour idv : ${idv}`);
    
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
        voteSubmitter(targetVoteHost, idv.substr(0, 20), pem)
        .then((result) => {
          setTimeout(() => {
            request.get(JSON.parse(result).link, (err, res) => {
              console.log(res.body);
            });
          }, 1000)
        })
        .catch((err) => {
          console.log(err);
        })
      });
    });
  });
});
