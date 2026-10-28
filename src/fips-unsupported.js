// kxco-post-quantum/fips outside Node.js. The module reads its own files for
// its integrity test and draws entropy from the operating system, so it runs on
// Node.js only. Anywhere else the import fails, rather than quietly offering
// services that never ran a self-test.

throw new Error('kxco-post-quantum/fips runs on Node.js only')
