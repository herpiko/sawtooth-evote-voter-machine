const fs = require('fs');
const request = require('request');
const base64 = require('js-base64').Base64;
const cbor = require('cbor')
const pg = require('pg');
const forge = require('node-forge');
const hash = require('hash.js')
const pki = forge.pki;
const nationalSubmitter = require('../sawtooth-evote-submitter/national-submitter');

const localVoteNode = process.argv[2];
const provinceVoteNode = process.argv[3];
if (!localVoteNode) {
  throw ("Please specify the node (node index host:port)");
}

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

const dump = (filter) => {
  return new Promise((resolve, reject) => {
    // In real world, this should be handled by dedicated driver
    // See : https://sawtooth.hyperledger.org/docs/core/releases/1.0/app_developers_guide/event_subscriptions.html
    let obj = {
      data: [],
      total: 0,
    }
    let next = true;
    let promises = [];
    let nextUrl;

    var get = (next) => {
      let uri = next || 'http://' + localVoteNode + '/transactions?limit=100';
      console.log('Fetching ' + uri);
      request.get({
        uri: uri
      }, (err, resp) => {
        if (err) {
          return reject(err);
        }
        let body = JSON.parse(resp.body);
        if (body.data && body.data.length > 0) {
          obj.total += body.data.length;
          for (var i in body.data) {
            // Ignore sawtooth related families
            if (body.data[i].header.family_name === 'sawtooth_settings') {
              obj.total--;
              continue;
            }
            let item = {};
            item['familyName'] = body.data[i].header.family_name;
            item['stateId'] = body.data[i].header.inputs[0];
            let buf = Buffer.from(body.data[i].payload, 'base64');
            let decoded = cbor.decode(buf);
            item['state'] = decoded.Value
            if (filter && filter.state && filter.state !== decoded.Value) {
              obj.total--;
              continue;
            }
            obj.data.push(item);
          }
        }
        if (body.paging && body.paging.next) {
          get(body.paging.next);
        } else {
          next = false;
          resolve(obj);
        }
      });
    }
    get();
  });
}

dump()
  .then((result) => {
    // C1 equivalent
    let machineCommonName
    for (var i in tpsCert.subject.attributes) {
      console.log((tpsCert.subject.attributes[i].name || tpsCert.subject.attributes[i].type) + ' : ' + tpsCert.subject.attributes[i].value);
      if (tpsCert.subject.attributes[i].name === 'commonName') {
        machineCommonName = tpsCert.subject.attributes[i].value;
      }
    }
    var idm = hash.sha256().update(machineCommonName).digest('hex');

    let transactions = [];
    let voterTransactions = []

    const query = 'SELECT * FROM dpt ORDER BY id ASC';
    pgclient.query(query, (err, res) => {
      if (err) {
        console.log(err);
        process.exit();
      }

      if (res.rows.length !== result.data.length) {
        console.log('Ballots count and voter\'s identities are not matched.');
        process.exit();
      }

      // Now collect the voters' identities
      for (let i in res.rows) {
        const voter = JSON.parse(base64.decode(res.rows[i].value));
        const id = hash.sha256().update(res.rows[i].id + (new Date()).valueOf() + Math.random()).digest('hex');
        voterTransactions.push({
          id: id.substr(0, 20),
          state: base64.encode(JSON.stringify(voter)),
        });
      }

      // Compile transaction
      for (let i in result.data) {
        let vote = JSON.parse(base64.decode(result.data[i].state));

        // Sign the encrypted bailout using MesinPemilih's key 
        var p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(vote.z);
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
        vote.m = forge.pkcs7.messageToPem(p7).replace(/\r?\n|\r/g, '').split('-----')[2];
        transactions.push({
          id: result.data[i].stateId,
          state: base64.encode(JSON.stringify(vote)),
        });
      }

      nationalSubmitter(provinceVoteNode, 'provinceVote', transactions)
        .then((result) => {
          setTimeout(() => {
            request.get(JSON.parse(result).link, (err, res) => {
              if (err) {
                console.log(err);
                return;
                process.exit();
              }
              console.log(res.body);
              let body = JSON.parse(res.body)
              if (body && body.data[0] && body.data[0].invalid_transactions && body.data[0].invalid_transactions.length > 0) {
                console.log(body.data[0].invalid_transactions[0]);
              }

              nationalSubmitter(provinceVoteNode, 'provinceVoter', voterTransactions)
                .then((result) => {
                  setTimeout(() => {
                    request.get(JSON.parse(result).link, (err, res) => {
                      if (err) {
                        console.log(err);
                        return;
                        process.exit();
                      }
                      console.log(res.body);
                      let body = JSON.parse(res.body)
                      if (body && body.data[0] && body.data[0].invalid_transactions && body.data[0].invalid_transactions.length > 0) {
                        console.log(body.data[0].invalid_transactions[0]);
                      }
                      process.exit();
                    });
                  }, 1000);
                });
            });
          }, 1000);
        })
        .catch((err) => {
          console.log(err);
        });
    });

  })
  .catch((err) => {
    console.log(err);
  });
