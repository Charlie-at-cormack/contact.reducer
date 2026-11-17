// Startup file for Plesk / Phusion Passenger (Application Startup File: app.cjs).
// Passenger loads the startup file with require(); server.js is an ES module, so load it with import().
// Locally, keep using `npm start`.
import('./server.js').catch((err) => {
  console.error(err);
  process.exit(1);
});
