/**
 * Simple Express server for CVE Assessment Dashboard
 * Handles proper URL routing without hashes as required by assessment
 */

const express = require('express');
const path = require('path');

const app = express();
const PORT = 3000;

// Serve static files first (CSS, JS, images, etc.)
app.use(express.static(__dirname));

// Define specific SPA routes that should serve index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/cves/list', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/cves/:cveId', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 CVE Assessment Dashboard running at:`);
    console.log(`📍 http://localhost:${PORT}`);
    console.log(`📋 List page: http://localhost:${PORT}/cves/list`);
    console.log(`📋 Example detail: http://localhost:${PORT}/cves/CVE-2023-1234`);
    console.log('');
    console.log('✅ Proper URL routing enabled (no hashes required)');
});

module.exports = app;
