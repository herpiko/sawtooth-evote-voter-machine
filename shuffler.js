const pg = require('pg');
const async = require('async');
const shuffle = require('shuffle-array');
const pgclient = new pg.Client({
  user: 'root',
  host: 'tps-1-db-1.skripsi.local',
  database: 'dpt',
  port:26257,
});
pgclient.connect();

const query = 'SELECT * FROM dpt;';
setInterval(() => {
  pgclient.query(query, (err, res) => {
    if (err) {
  	  console.log(err);
  		process.exit();
  	}
    let rows = res.rows;
    if (rows.length < 1) return;
    let ids = [];
    for (let i in rows) {
      ids.push(rows[i].id);
    }
    console.log('randomizing:');
    console.log(rows);
    shuffle(rows);
    for (let i in ids) {
      rows[i].id = ids[i];
    }
    async.eachSeries(rows, (row, cb) => {
      const q = 'UPDATE dpt SET key=$1, value=$2 WHERE id=$3';
      const values = [row.key, row.value, row.id];
      pgclient.query(q, values, (err, res) => {
        cb(err);
      })
    }, (err) => {
      if (err) {
        console.log(err);
        process.exit();
      }
      console.log('randomized:');
      console.log(rows);
    });
   
  });
}, 1000);
