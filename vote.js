const fs = require('fs');
const pg = require('pg');
const prompt = require('prompt');
const {createHash} = require('crypto')
const {spawnSync} = require('child_process');
const forge = require('node-forge');
const cbor = require('cbor')
const pbkdf2 = require('pbkdf2');
const request = require('request');
const ed25519 = require('ed25519');
const aes256 = require('aes256');
const hash = require('hash.js')
const pki = forge.pki;
const base64 = require('js-base64').Base64;
const arrayBufferToBuffer = require('arraybuffer-to-buffer')
const tpsSubmitter = require('../sawtooth-evote-submitter/tps-submitter');
const targetDPTHost = process.argv[3] || '172.30.0.111:21311'
const atob = require('atob');
const targetVoteHost = process.argv[3] || '172.30.0.211:22311'
const publicKey = '0c32c468980d40237f4e44a66dec3beb564b3e1394a4c6df1da2065e3afc1d81';
const p = new Buffer(publicKey, 'hex');

const config = JSON.parse(fs.readFileSync('config.json', 'utf8'));

const pgclient = new pg.Client({
  user: 'root',
  host: 'localhost',
  database: 'dpt',
  port: 23111,
});
pgclient.connect();

// TPS key pair
const certPem = fs.readFileSync('../sawtooth-evote-ejbca/KPU_Machines/TPS/527105_001/tps_527105_001.pem', 'utf8');
const tpsCert = pki.certificateFromPem(certPem);
const keyPem = fs.readFileSync('../sawtooth-evote-ejbca/KPU_Machines/TPS/527105_001/tps_527105_001.plain.key', 'utf8');
const tpsKey = pki.privateKeyFromPem(keyPem);

// Kunci Suara
const kunciSuaraPem = fs.readFileSync('../sawtooth-evote-ejbca/KPU_Machines/KunciSuara/kunci_suara.pem', 'utf8');
const kunciSuara = pki.certificateFromPem(kunciSuaraPem);
const kunciSuaraPKPem = fs.readFileSync('../sawtooth-evote-ejbca/KPU_Machines/KunciSuara/kunci_suara.plain.key', 'utf8');
const kunciSuaraPK = pki.certificateFromPem(kunciSuaraPem);

prompt.start();
const schema = {
  properties: {
    cert: {
      message: 'Cert path',
      required: true,
      default: '../sawtooth-evote-ejbca/Dukcapil_DPT/' + (process.argv[2] === 'saeful' ? 'saeful_bahri.pem' : process.argv[2] === 'ayu' ? 'ayu_septiani.pem' : 'herpiko_dwi_aguno.pem')
    },
    key: {
      message: 'Key path',
      required: true,
      default: '../sawtooth-evote-ejbca/Dukcapil_DPT/' + (process.argv[2] === 'saeful' ? 'saeful_bahri.plain.key' : process.argv[2] === 'ayu' ? 'ayu_septiani.plain.key' : 'herpiko_dwi_aguno.plain.key')
    },
    kValue: {
      message: 'k Value',
      required: true,
    },
  }
}

function base64ToArrayBuffer(base64) {
  var binary_string = atob(base64);
  var len = binary_string.length;
  var bytes = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
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
  } catch ( e ) {
    console.log('\nError : eKTP is not verified');
    return;
  }

  // Verify against CRL
  console.log('Verifying cert against CRL...');
  let spawned = spawnSync('openssl', ['verify', '-crl_check', '-CAfile', '../sawtooth-evote-ejbca/CA/DukcapilIntermediateCA-crl-chain.pem', result.cert]);
  let crlCheckResult = spawned.stdout.toString().indexOf('OK') > -1
  console.log(crlCheckResult ? '- Verified\n' : '- Not verified / revoked');
  if (!crlCheckResult) {
    console.log(spawned.stdout.toString());
    console.log(spawned.stderr.toString());
    return;
  }

  // Check the voter id against local DPT ledger. The state should be ready, otherwise, abort.
  let familyName = 'localDPT';
  let nameHash = createHash('sha256').update(commonName).digest('hex')
  let payloadNameHash = createHash('sha512').update(nameHash).digest('hex');
  let familyNameHash = createHash('sha512').update(familyName).digest('hex');
  let stateId = familyNameHash.substr(0, 6) + payloadNameHash.substr(-64);
  request.get('http://' + targetDPTHost + '/state/' + stateId, (err, res) => {
    if (err) {
      console.log(err);
      return;
    }
    console.log(res.body)
    let buf = Buffer.from(JSON.parse(res.body).data, 'base64');
    let decoded = cbor.decode(buf);
    let keys = Object.keys(decoded);
    if (decoded[keys[0]] !== 'ready') {
      console.log(decoded[keys[0]]);
      console.log('VoterID is NOT READY to vote. Aborted.');
      return;
    }

    // Verify the k value aginst KPU Server's  ed25519 public key
    console.log(kValue.split('_')[1])
    console.log(kValue.split('_')[2])
    let signatureAb = base64ToArrayBuffer(kValue.split('_')[2]);
    let signature = arrayBufferToBuffer(signatureAb);
    let msg = new Buffer(kValue.split('_')[1]);
    try {
      if (!ed25519.Verify(msg, signature, p)) {
        console.log('K value signature is not verified. Aborted.');
        return;
      }
    } catch ( e ) {
      console.log(e);
      console.log('K value signature is not verified. Aborted.');
      return;
    }
    // Check the k value aginst voter identity
    const x = pbkdf2.pbkdf2Sync(kValue.split('_')[0], commonName, 1, 32, 'sha512').toString('base64');
    if (x !== kValue.split('_')[1]) {
      console.log('This is not your k value. Aborted.');
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
        properties: {
          vote: {
            message: candidatesPrompt,
            required: true,
          },
        }
      }
      candidatesPrompt += '\n\nPlease vote (enter number)';
      prompt.get(voteSchema, (err, result) => {

        const vote = parseInt(result.vote); // c value represented by this vote variable
        if (vote < 0 || vote > candidates.length) {
          console.log(vote + ' is not a valid candidate');
          process.exit(1);
        }
        // Generate idv from kdf k (NIK) 
        const idv = pbkdf2.pbkdf2Sync(kValue, commonName, 1, 32, 'sha512').toString('base64') + kValue.substr(45);
        console.log(`
Your k : ${kValue}`);
        console.log(`
Your idv : ${idv}`);

        // Encrypt the bailout value using Kunci Suara 
        var p7 = forge.pkcs7.createEnvelopedData();
        p7.addRecipient(kunciSuara);
        p7.content = forge.util.createBuffer(vote.toString());
        p7.encrypt();
        try {
          p7.decrypt(p7.recipients[i], kunciSuaraPK)
        } catch(e) {
          console.log(e);
          process.exit();
        }
        let z = forge.pkcs7.messageToPem(p7);
        //replace(/\r?\n|\r/g, '').split('-----')[2];

        // Sign the encrypted bailout using MesinPemilih's key 
        var p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(z);
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
        p7.sign({detached:true});
        var zs = forge.pkcs7.messageToPem(p7);//.replace(/\r?\n|\r/g, '').split('-----')[2];
        // Now we have z value


        // Sign the encrypted bailout using voter's key
        var p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(vote.toString());
        p7.addCertificate(tpsCert);
        p7.addSigner({
          key: voterKey,
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
        p7.sign({detached:true});
        var o = forge.pkcs7.messageToPem(p7);

        // Encrypt the bailout using k value
        let nObj = { vote : vote.toString(), signature: o }
        var n = aes256.encrypt(kValue, JSON.stringify(nObj))

        // Now we have a complete secured bailout        
        let payload = {};
        payload[idv] = {
          z: z, // this is for KPU
          zs: zs, // the signature of z by tps key
          n: n // this is for user to verify in the future
        }
        console.log('\nPayload : ' + JSON.stringify(payload));

        // It's time to mark the voter as already vote. Create the payload first.
        let machineCommonName
        for (var i in tpsCert.subject.attributes) {
          console.log((tpsCert.subject.attributes[i].name || tpsCert.subject.attributes[i].type) + ' : ' + tpsCert.subject.attributes[i].value);
          if (tpsCert.subject.attributes[i].name === 'commonName') {
            machineCommonName = tpsCert.subject.attributes[i].value;
          }
        }
        var idm = hash.sha256().update(machineCommonName).digest('hex');

        let a = hash.sha256().update(commonName).digest('hex');
        var p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(z);
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
        }, {
          key: voterKey,
          certificate: voterCert,
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
        var q = forge.pkcs7.messageToPem(p7).replace(/\r?\n|\r/g, '').split('-----')[2];


        // Submit it to local voter ledger
        tpsSubmitter(targetVoteHost, 'localVote', idv.substr(0, 20), base64.encode(JSON.stringify(payload)))
          .then((result) => {
            setTimeout(() => {
              request.get(JSON.parse(result).link, (err, res) => {
                console.log(res.body);
                let body = JSON.parse(res.body)
                if (body && body.data[0] && body.data[0].invalid_transactions && body.data[0].invalid_transactions.length > 0) {
                  console.log(body.data[0].invalid_transactions[0]);
                  return;
                }

                // Submit it to cockroach db cluster
                let payload = {};
                payload[idm] = q;
                payload['commonName'] = commonName;
                console.log('\nPayload : ' + JSON.stringify(payload));
                /* localDPT no longer receive payload
                tpsSubmitter(targetDPTHost, 'localDPT', idm.substr(0, 20), base64.encode(JSON.stringify(payload)))
                .then((result) => {
                  setTimeout(() => {
                    request.get(JSON.parse(result).link, (err, res) => {
                      console.log(res.body);
                    });
                  }, 2000)
                })
                .catch((err) => {
                  console.log(err);
                })
                */
                const query = 'INSERT INTO dpt (key, value) values ($1, $2);';
                const values = [idm.substr(0, 20), base64.encode(JSON.stringify(payload))];
                pgclient.query(query, values, (err, res) => {
                  console.log(err);
                  console.log(res);
                  process.exit();
                });
              });
            }, 2000)
          })
          .catch((err) => {
            console.log(err);
            process.exit();
          })
      });
    });
  });
});
