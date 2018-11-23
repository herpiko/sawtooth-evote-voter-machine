const fs = require('fs');
const {createHash} = require('crypto')
const express = require('express');
const bodyParser = require('body-parser');
const ed25519 = require('ed25519');
const request = require('request');
const cbor = require('cbor')
const base64 = require('js-base64').Base64;
const app = express();
const port = process.env.PORT || 3333
const dptNode = process.argv[2];
const voteNode = process.argv[3];
const https = require('https');
if (!dptNode) throw("Please specify the node (node index host:port)");
if (!voteNode) throw("Please specify the node (node index host:port)");

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:true}));

// TODO mutual auth

const dump = (node, filter) => {
  return new Promise((resolve, reject) => {
    // In real world, this handled by dedicated driver
    // See : https://sawtooth.hyperledger.org/docs/core/releases/1.0/app_developers_guide/event_subscriptions.html
    let obj = {
      data : [],
      total : 0,
    }
    let next = true;
    let promises = [];
    let nextUrl;
  
    var get = (next) => {
      let uri = next || 'http://' + node + '/transactions?limit=100';
      console.log('Fetching ' + uri);
      request.get({uri: uri}, (err, resp) => {
        if (err) return reject(err);
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

app.get('/', (req, res) => {
  let DPTTXs
  let VoteTXs
  console.log('ok')
  dump(dptNode)
  .then((result) => {
    DPTTXs = result;
    return dump(voteNode)
  })
  .then((result) => {
    VoteTXs = result;
    for (let i in VoteTXs.data) {
      delete(VoteTXs.data[i].state);
      delete(VoteTXs.data[i].familyName);
    }
    res.send(VoteTXs);
  })
  .catch((err) => {
    res.send(err);
  });

/*
  let body = 'Evote<br/>local DPT ledger : ' + dptNode;
  body += '<br/>local Vote ledger : ' + dptNode;
  body += '<ul>';
  body += '<li><a href="/api/dpt-transactions">DPT transactions</a></li>';
  body += '<li><a href="/api/dpt-dump">DPT dump</a></li>';
  body += '</ul>';
  res.send(body);
*/
});

app.get('/api/verify/:id', (req, res) => { // Voter checking their commited bailoud
  request.get({uri: 'http://' + voteNode + '/state/' + req.params.id}, (err, resp) => {
    if (err) return res.send({error : err});
    let body = JSON.parse(resp.body);
    let data = body.data;
    if (!data) {
      return res.send({status : 'NOT_EXISTS'});
    }
    let buf = Buffer.from(data, 'base64');
    let decoded = cbor.decode(buf);
    let keys = Object.keys(decoded);
    let payload;
    for (let i in keys) {
      payload = decoded[keys[i]]
    }
    payload = JSON.parse(base64.decode(payload))
    keys = Object.keys(payload);
    let d
    for (let i in keys) {
      d = payload[keys[i]]
    }
    console.log(d)
    res.send(d.o);
  });
});

app.listen(port, function(){
  console.log('Evote server started on port ' + port + ' against ledger ' + dptNode + ', ' + voteNode);
})
