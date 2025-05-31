// General functions for all tools
function setupToolForm(formId, endpoint, processResults) {
    const form = document.getElementById(formId);
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(form);
        const submitBtn = form.querySelector('button[type="submit"]');
        
        submitBtn.disabled = true;
        submitBtn.textContent = 'Processing...';

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            processResults(data);
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred. Please try again.');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Submit';
        }
    });
}

// Initialize tool-specific scripts when on their pages
document.addEventListener('DOMContentLoaded', function() {
    // Check which page we're on and initialize accordingly
    const path = window.location.pathname;
    
    if (path === '/traffic') {
        // Initialize traffic analyzer 
        initTrafficAnalyzer();
    } else if (path === '/vulnerability') {
        setupToolForm('vulnerabilityForm', '/vulnerability/scan', displayVulnerabilityResults);
    } else if (path === '/encryption') {
        setupToolForm('encryptionForm', '/encryption/process', displayEncryptionResults);
    } else if (path === '/phishing') {
        setupToolForm('phishingForm', '/phishing/check', displayPhishingResults);
    } else if (path === '/hashing') {
        setupToolForm('hashingForm', '/hashing/generate', displayHashingResults);
    }
});

// Tool-specific result handlers
function displayVulnerabilityResults(data) {
    const resultsDiv = document.getElementById('results');
    let html = '<h3>Scan Results</h3>';
    
    if (data.server_info) {
        html += `<p><strong>Server:</strong> ${data.server_info}</p>`;
    }
    
    if (data.open_ports.length > 0) {
        html += `<p><strong>Open Ports:</strong> ${data.open_ports.join(', ')}</p>`;
    } else {
        html += `<p>No common open ports found</p>`;
    }
    
    if (data.vulnerabilities.length > 0) {
        html += '<p><strong>Potential Vulnerabilities:</strong></p><ul>';
        data.vulnerabilities.forEach(vuln => {
            html += `<li>${vuln}</li>`;
        });
        html += '</ul>';
    } else {
        html += '<p>No obvious vulnerabilities detected</p>';
    }
    
    resultsDiv.innerHTML = html;
}

function displayEncryptionResults(data) {
    document.getElementById('resultOutput').value = data.result;
}

function displayPhishingResults(data) {
    const resultsDiv = document.getElementById('results');
    let html = '<h3>Phishing Check Results</h3>';
    
    html += `<p><strong>Domain:</strong> ${data.domain}</p>`;
    html += `<p><strong>Suspicious:</strong> ${data.suspicious ? 'Yes' : 'No'}</p>`;
    html += `<p><strong>In Phishing DB:</strong> ${data.in_phishing_db ? 'Yes' : 'No'}</p>`;
    html += `<p><strong>Message:</strong> ${data.message}</p>`;
    
    resultsDiv.innerHTML = html;
}

function displayHashingResults(data) {
    document.getElementById('hashOutput').value = data.hash;
}