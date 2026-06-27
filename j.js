function analyzeUrl() {
    const urlInput = document.getElementById('urlInput').value.trim();
    const resultsDiv = document.getElementById('results');
    const reportList = document.getElementById('reportList');
    
    // Clear previous results and show the results box
    reportList.innerHTML = '';
    resultsDiv.classList.remove('hidden');

    if (!urlInput) {
        addReportItem('Please enter a URL to analyze.', 'warning');
        return;
    }

    try {
        // Force a protocol if the user didn't type one so our parser doesn't crash
        let urlString = urlInput;
        if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
            urlString = 'http://' + urlString;
        }
        
        const parsedUrl = new URL(urlString);
        let riskScore = 0;

        // Tactic 1: Unencrypted connection
        if (parsedUrl.protocol === 'http:') {
            addReportItem('⚠️ Protocol Risk: Uses HTTP instead of HTTPS. Data is not encrypted.', 'warning');
            riskScore++;
        } else {
            addReportItem('✅ Secure Protocol: Uses standard HTTPS encryption.', 'safe');
        }

        // Tactic 2: IP Address instead of a domain name
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (ipRegex.test(parsedUrl.hostname)) {
            addReportItem('⚠️ IP Obfuscation: Uses a raw IP address instead of a domain name. Highly suspicious.', 'warning');
            riskScore++;
        }

        // Tactic 3: Too many subdomains (trying to fake a brand)
        const domainParts = parsedUrl.hostname.split('.');
        if (domainParts.length > 3 && !ipRegex.test(parsedUrl.hostname)) {
            addReportItem('⚠️ Subdomain Risk: Unusually high number of subdomains detected. Attackers use this to hide the real destination.', 'warning');
            riskScore++;
        }

        // Tactic 4: URL Length
        if (urlInput.length > 75) {
            addReportItem('⚠️ Length Risk: The URL is excessively long, often used to hide malicious parameters.', 'warning');
            riskScore++;
        }

        // Final Assessment
        if (riskScore === 0) {
            addReportItem('🟢 Final Verdict: No immediate red flags detected by basic heuristics.', 'safe');
        } else {
            addReportItem(`🔴 Final Verdict: Found ${riskScore} potential risk factors. Proceed with extreme caution.`, 'warning');
        }

    } catch (error) {
        addReportItem('❌ Invalid URL format. Please check your spelling.', 'warning');
    }
}

// Helper function to draw the results on the screen
function addReportItem(text, type) {
    const li = document.createElement('li');
    li.textContent = text;
    li.className = type;
    document.getElementById('reportList').appendChild(li);
}