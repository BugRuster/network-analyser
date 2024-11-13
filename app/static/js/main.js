// Global variables for scan state
let scanInProgress = false;
let statusPollInterval = null;

document.addEventListener('DOMContentLoaded', () => {
    // Initialize event listeners
    document.getElementById('startScan').addEventListener('click', startScan);
});

function startScan() {
    if (scanInProgress) {
        showAlert('A scan is already in progress', 'warning');
        return;
    }

    const target = document.getElementById('target').value;
    const ports = document.getElementById('ports').value;
    const serviceScan = document.getElementById('service_scan').checked;
    const vulnScan = document.getElementById('vuln_scan').checked;
    
    if (!target) {
        showAlert('Please enter a target host/network', 'error');
        return;
    }
    
    // Show progress section and hide previous results
    document.getElementById('progress-section').classList.remove('hidden');
    document.getElementById('results-section').classList.add('hidden');
    document.getElementById('progress-bar').style.width = '0%';
    document.getElementById('status-message').textContent = 'Initializing scan...';
    
    scanInProgress = true;
    
    // Start the scan
    fetch('/start_scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            target: target,
            ports: ports,
            options: {
                service_scan: serviceScan,
                vuln_scan: vulnScan
            }
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            startStatusPolling();
        } else {
            showAlert(data.error, 'error');
            scanInProgress = false;
        }
    })
    .catch(error => {
        showAlert('Error: ' + error, 'error');
        scanInProgress = false;
    });
}

function startStatusPolling() {
    if (statusPollInterval) {
        clearInterval(statusPollInterval);
    }
    statusPollInterval = setInterval(pollStatus, 1000);
}

function pollStatus() {
    fetch('/scan_status')
        .then(response => response.json())
        .then(data => {
            updateProgress(data);
            
            if (data.status === 'completed' || data.status === 'error') {
                clearInterval(statusPollInterval);
                scanInProgress = false;
                
                if (data.status === 'completed') {
                    fetchResults();
                }
            }
        })
        .catch(error => {
            clearInterval(statusPollInterval);
            scanInProgress = false;
            showAlert('Error polling status: ' + error, 'error');
        });
}

function updateProgress(data) {
    const progressBar = document.getElementById('progress-bar');
    const statusMessage = document.getElementById('status-message');
    
    progressBar.style.width = data.progress + '%';
    statusMessage.textContent = data.message;
    
    if (data.status === 'error') {
        progressBar.classList.remove('bg-blue-600');
        progressBar.classList.add('bg-red-600');
        scanInProgress = false;
    }
}

function fetchResults() {
    fetch('/scan_results')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displayResults(data);
            } else {
                showAlert(data.error, 'error');
            }
        })
        .catch(error => {
            showAlert('Error fetching results: ' + error, 'error');
        });
}

function displayResults(results) {
    const resultsSection = document.getElementById('results-section');
    const resultsContent = document.getElementById('results-content');
    resultsSection.classList.remove('hidden');
    
    // Update security score if available
    if (results.summary && results.summary.security_score !== undefined) {
        updateSecurityScore(results.summary.security_score);
    }
    
    // Display vulnerability summary if available
    if (results.summary && results.summary.vulnerabilities) {
        updateVulnerabilitySummary(results.summary.vulnerabilities);
    }
    
    // Generate detailed results HTML
    let html = '<div class="space-y-6">';
    
    results.data.forEach(host => {
        html += generateHostSection(host);
    });
    
    html += '</div>';
    resultsContent.innerHTML = html;
}

function updateSecurityScore(score) {
    const scoreElement = document.getElementById('security-score');
    const scoreBar = document.getElementById('security-score-bar');
    
    if (scoreElement && scoreBar) {
        scoreElement.textContent = `Security Score: ${score}/100`;
        scoreBar.style.width = `${score}%`;
        
        // Update color based on score
        const colorClass = score >= 80 ? 'bg-green-500' : 
                         score >= 60 ? 'bg-yellow-500' : 
                         score >= 40 ? 'bg-orange-500' : 'bg-red-500';
        
        scoreBar.className = `shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center ${colorClass}`;
    }
}

function updateVulnerabilitySummary(vulnerabilities) {
    const severityDiv = document.getElementById('severity-distribution');
    const categoryDiv = document.getElementById('category-distribution');
    
    if (severityDiv) {
        const severityHTML = Object.entries(vulnerabilities.severity_counts)
            .map(([severity, count]) => {
                const colorClass = {
                    'Critical': 'bg-red-500',
                    'High': 'bg-orange-500',
                    'Medium': 'bg-yellow-500',
                    'Low': 'bg-green-500'
                }[severity] || 'bg-gray-500';
                
                return `
                    <div class="flex items-center justify-between">
                        <span class="px-2 py-1 rounded text-sm ${colorClass} text-white">${severity}</span>
                        <span class="font-semibold">${count}</span>
                    </div>
                `;
            }).join('');
        severityDiv.innerHTML = severityHTML;
    }
    
    if (categoryDiv && vulnerabilities.categories) {
        const categoryHTML = Object.entries(vulnerabilities.categories)
            .map(([category, count]) => `
                <div class="flex items-center justify-between">
                    <span>${category}</span>
                    <span class="font-semibold">${count}</span>
                </div>
            `).join('');
        categoryDiv.innerHTML = categoryHTML;
    }
}

function generateHostSection(host) {
    return `
        <div class="bg-white rounded-lg shadow-md p-6">
            <div class="mb-4">
                <h3 class="text-xl font-semibold">Host: ${host.host}</h3>
                ${host.hostname ? `<p class="text-gray-600">Hostname: ${host.hostname}</p>` : ''}
                <p class="text-gray-600">State: ${host.state}</p>
            </div>
            
            ${generatePortsSection(host.ports)}
            ${generateVulnerabilitiesSection(host.vulnerabilities)}
            ${generateRecommendationsSection(host.security_recommendations)}
        </div>
    `;
}

function generatePortsSection(ports) {
    if (!ports || ports.length === 0) {
        return '<p class="text-gray-600">No open ports found</p>';
    }
    
    return `
        <div class="mb-6">
            <h4 class="text-lg font-semibold mb-2">Open Ports & Services</h4>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Port</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Service</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Version</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">State</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Product</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        ${ports.map(port => `
                            <tr>
                                <td class="px-6 py-4 whitespace-nowrap">${port.port}</td>
                                <td class="px-6 py-4 whitespace-nowrap">${port.service || 'Unknown'}</td>
                                <td class="px-6 py-4 whitespace-nowrap">${port.version || 'Unknown'}</td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                        port.state === 'open' ? 'bg-green-100 text-green-800' :
                                        port.state === 'filtered' ? 'bg-yellow-100 text-yellow-800' :
                                        'bg-red-100 text-red-800'
                                    }">
                                        ${port.state}
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">${port.product || 'Unknown'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

function generateVulnerabilitiesSection(vulnerabilities) {
    if (!vulnerabilities || vulnerabilities.length === 0) {
        return '<div class="mb-6"><p class="text-gray-600">No vulnerabilities detected</p></div>';
    }
    
    return `
        <div class="mb-6">
            <h4 class="text-lg font-semibold mb-2">Detected Vulnerabilities</h4>
            <div class="space-y-4">
                ${vulnerabilities.map(vuln => `
                    <div class="border-l-4 ${getSeverityColorClass(vuln.severity)} bg-gray-50 p-4">
                        <div class="flex justify-between">
                            <h5 class="font-semibold">${vuln.id}</h5>
                            <span class="px-2 py-1 text-sm rounded ${getSeverityBgClass(vuln.severity)}">
                                ${vuln.severity}
                            </span>
                        </div>
                        <p class="text-sm mt-2">${vuln.output}</p>
                        ${vuln.cve_numbers.length > 0 ? `
                            <div class="mt-2">
                                <span class="text-sm font-semibold">CVE References:</span>
                                <div class="flex flex-wrap gap-2 mt-1">
                                    ${vuln.cve_numbers.map(cve => `
                                        <span class="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-gray-100 text-gray-800">
                                            ${cve}
                                        </span>
                                    `).join('')}
                                </div>
                            </div>
                        ` : ''}
                        <div class="mt-2">
                            <span class="text-sm font-semibold">Remediation:</span>
                            <p class="text-sm mt-1">${vuln.remediation}</p>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

function generateRecommendationsSection(recommendations) {
    if (!recommendations || recommendations.length === 0) {
        return '';
    }
    
    return `
        <div class="mb-6">
            <h4 class="text-lg font-semibold mb-2">Security Recommendations</h4>
            <ul class="list-disc list-inside space-y-2">
                ${recommendations.map(rec => `
                    <li class="text-gray-700">${rec}</li>
                `).join('')}
            </ul>
        </div>
    `;
}

function getSeverityColorClass(severity) {
    switch (severity.toLowerCase()) {
        case 'critical': return 'border-red-500';
        case 'high': return 'border-orange-500';
        case 'medium': return 'border-yellow-500';
        case 'low': return 'border-green-500';
        default: return 'border-gray-500';
    }
}

function getSeverityBgClass(severity) {
    switch (severity.toLowerCase()) {
        case 'critical': return 'bg-red-100 text-red-800';
        case 'high': return 'bg-orange-100 text-orange-800';
        case 'medium': return 'bg-yellow-100 text-yellow-800';
        case 'low': return 'bg-green-100 text-green-800';
        default: return 'bg-gray-100 text-gray-800';
    }
}

function showAlert(message, type = 'error') {
    const alertDiv = document.createElement('div');
    const bgColor = type === 'error' ? 'bg-red-500' :
                   type === 'warning' ? 'bg-yellow-500' :
                   'bg-green-500';
    
    alertDiv.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg ${bgColor} text-white max-w-md z-50`;
    
    alertDiv.innerHTML = `
        <div class="flex items-center justify-between">
            <span class="flex-grow mr-4">${message}</span>
            <button class="hover:opacity-75 focus:outline-none">
                <svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                </svg>
            </button>
        </div>
    `;
    
    alertDiv.querySelector('button').addEventListener('click', () => {
        alertDiv.remove();
    });
    
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}