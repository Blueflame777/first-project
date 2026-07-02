
function toggleMenu() {
    const sideMenu = document.getElementById('sideMenu');
    sideMenu.classList.toggle('open');
}

let riskChartInstance = null;


class URLScanner {
    constructor(rawUrl) {
        this.rawUrl = rawUrl.trim();
        this.score = 0;
        this.logs = [];
        this.parsedUrl = null;
        
        this.suspiciousTLDs = ['.xyz', '.top', '.tk', '.pw', '.cc', '.club', '.work', '.info', '.online', '.ru', '.cn'];
        this.shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'];
        this.targetBrands = ['paypal', 'google', 'apple', 'microsoft', 'amazon', 'netflix', 'facebook', 'chase', 'bank', 'whatsapp'];
        this.badKeywords = ['login', 'verify', 'update', 'secure', 'account', 'auth', 'wallet', 'invoice', 'suspend'];
        this.malwareExtensions = ['.exe', '.apk', '.bat', '.scr', '.msi', '.zip', '.rar', '.tar.gz'];
    }

    log(message, weight) {
        this.logs.push({ message, weight });
        this.score += weight;
    }

    init() {
        if (!this.rawUrl) throw new Error("Input is empty. Please provide a target URL.");
        let processUrl = this.rawUrl;
        if (!processUrl.startsWith('http://') && !processUrl.startsWith('https://')) {
            processUrl = 'http://' + processUrl;
        }
        try {
            this.parsedUrl = new URL(processUrl);
        } catch (e) {
            throw new Error("Malformed URL. Cannot parse the target.");
        }
    }

    calculateEntropy(str) {
        const len = str.length;
        if (len === 0) return 0;
        const frequencies = Array.from(str).reduce((freq, c) => (freq[c] = (freq[c] || 0) + 1, freq), {});
        return Object.values(frequencies).reduce((sum, f) => sum - (f / len) * Math.log2(f / len), 0);
    }

    calculateLevenshtein(a, b) {
        if (a.length === 0) return b.length;
        if (b.length === 0) return a.length;
        const matrix = Array.from({length: b.length + 1}, (_, i) => [i]);
        for (let j = 1; j <= a.length; j++) matrix[0][j] = j;
        for (let i = 1; i <= b.length; i++) {
            for (let j = 1; j <= a.length; j++) {
                if (b.charAt(i - 1) === a.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1));
                }
            }
        }
        return matrix[b.length][a.length];
    }

    analyze() {
        this.init();
        const hostname = this.parsedUrl.hostname.toLowerCase();
        const fullPath = (this.parsedUrl.pathname + this.parsedUrl.search).toLowerCase();

        // 1. IP Address Check
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (ipRegex.test(hostname)) {
            this.log("[CRITICAL] Hostname is a raw IP address.", 40);
        }

        // 2. Typosquatting Analysis
        const domainWithoutTLD = hostname.substring(0, hostname.lastIndexOf('.'));
        this.targetBrands.forEach(brand => {
            const distance = this.calculateLevenshtein(domainWithoutTLD, brand);
            if (distance > 0 && distance <= 2) {
                this.log(`[WARNING] Typosquatting risk. Domain is 1-2 letters away from '${brand}'.`, 15);
            }
            if (this.rawUrl.toLowerCase().includes(brand) && !hostname.includes(`${brand}.`)) {
                this.log(`[CRITICAL] Brand spoofing attempt. Found '${brand}' in path/subdomain.`, 45);
            }
        });

        // 3. Gibberish Detection
        const pathEntropy = this.calculateEntropy(this.parsedUrl.pathname);
        if (pathEntropy > 4.0) {
            this.log(`[WARNING] High URL Entropy (${pathEntropy.toFixed(2)}). Indicates randomly generated strings.`, 20);
        }

        // 4. Punycode
        if (hostname.includes('xn--')) {
            this.log("[CRITICAL] Punycode detected (xn--). Domain is using foreign characters to spoof an English domain.", 50);
        }

        // 5. Port Check
        if (this.parsedUrl.port && !['80', '443'].includes(this.parsedUrl.port)) {
            this.log(`[WARNING] Non-standard web port detected (${this.parsedUrl.port}).`, 20);
        }

        // 6. Credentials Check
        if (this.parsedUrl.username || this.parsedUrl.password) {
            this.log("[CRITICAL] URL contains embedded credentials. Highly deceptive routing tactic.", 45);
        }

        // 7. NEW: Payload & File Extension Analysis
        const foundExtension = this.malwareExtensions.find(ext => fullPath.endsWith(ext));
        if (foundExtension) {
            this.log(`[CRITICAL] Suspicious file extension detected (${foundExtension}). Potential malware payload.`, 45);
        }

        // 8. NEW: URL Encoding Obfuscation Check
        const encodingCount = (this.rawUrl.match(/%/g) || []).length;
        if (encodingCount > 5) {
            this.log(`[WARNING] High level of URL encoding detected (${encodingCount} encoded characters). Possible obfuscation attempt.`, 20);
        }

        // 9. NEW: "Double TLD" Deception
        const commonTLDs = ['.com.', '.net.', '.org.', '.gov.', '.edu.', '.co.'];
        if (commonTLDs.some(tld => hostname.includes(tld))) {
            this.log("[CRITICAL] Double TLD detected in the hostname. This is a common brand spoofing technique.", 40);
        }

        // 10. NEW: Excessive Path Depth
        const pathDepth = (this.parsedUrl.pathname.match(/\//g) || []).length;
        if (pathDepth >= 5) {
            this.log(`[WARNING] Excessive path depth detected (${pathDepth} levels). Phishing pages are often hidden deep within compromised sites.`, 15);
        }

        // 11. Standard Checks (TLDs, Shorteners, Hyphens, Keywords)
        const tldMatch = hostname.match(/\.[a-z]+$/);
        if (tldMatch && this.suspiciousTLDs.includes(tldMatch[0])) this.log(`[WARNING] Low-trust Top Level Domain (${tldMatch[0]}).`, 20);
        
        if (this.shorteners.includes(hostname)) this.log("[WARNING] URL Shortener detected. Destination is hidden.", 25);
        
        const hyphenCount = (hostname.match(/-/g) || []).length;
        if (hyphenCount > 2) this.log(`[WARNING] Excessive hyphens (${hyphenCount}). Used in typosquatting.`, 15);

        let foundKeywords = this.badKeywords.filter(word => fullPath.includes(word) || hostname.includes(word));
        if (foundKeywords.length > 0) this.log(`[WARNING] Social engineering keywords: ${foundKeywords.join(', ')}`, 10 * foundKeywords.length);

        if (this.score > 100) this.score = 100;
        if (this.score === 0) this.log("[SAFE] No immediate lexical threats detected.", 0);

        return { score: this.score, logs: this.logs };
    }
}

function triggerScan() {
    const input = document.getElementById('urlInput').value.trim();
    const resultsDiv = document.getElementById('results');
    const loadingState = document.getElementById('loadingState');
    
    if (!input) {
        alert("Please paste a URL to scan.");
        return;
    }
    resultsDiv.classList.add('hidden');
    loadingState.classList.remove('hidden');
    setTimeout(() => {
        loadingState.classList.add('hidden');
        processResults(input);
    }, 1500);
}

function processResults(input) {
    const resultsDiv = document.getElementById('results');
    const reportList = document.getElementById('reportList');
    const scoreValue = document.getElementById('scoreValue');

    reportList.innerHTML = ''; 
    resultsDiv.classList.remove('hidden');

    try {
        const scanner = new URLScanner(input);
        const report = scanner.analyze();

  
        let scoreColor = '#3fb950';
        let colorClass = 'risk-low';
        
        if (report.score >= 20 && report.score < 60) {
            scoreColor = '#d29922'; 
            colorClass = 'risk-med';
        } else if (report.score >= 60) {
            scoreColor = '#f85149'; 
            colorClass = 'risk-high';
        }

        scoreValue.textContent = report.score;
        scoreValue.className = colorClass;

        renderChart(report.score, scoreColor);

    
        report.logs.forEach(log => {
            const li = document.createElement('li');
            li.textContent = log.message;
            if (log.weight >= 40) {
                li.style.borderLeftColor = '#f85149'; 
                li.style.boxShadow = 'inset 5px 0 10px -5px rgba(248, 81, 73, 0.2)';
            } else if (log.weight > 0) {
                li.style.borderLeftColor = '#d29922'; 
                li.style.boxShadow = 'inset 5px 0 10px -5px rgba(210, 153, 34, 0.2)';
            } else {
                li.style.borderLeftColor = '#3fb950'; 
                li.style.boxShadow = 'inset 5px 0 10px -5px rgba(63, 185, 80, 0.2)';
            }
            reportList.appendChild(li);
        });

    } catch (error) {
        scoreValue.textContent = "ERR";
        scoreValue.className = 'risk-high';
        try {
            if (typeof Chart !== 'undefined') {
                renderChart(100, '#f85149'); 
            }
        } catch(e) {
            console.error("Chart failed to render", e);
        }
        
        const li = document.createElement('li');
        li.textContent = `❌ ${error.message}`;
        li.style.borderLeftColor = '#f85149';
        li.style.boxShadow = 'inset 5px 0 10px -5px rgba(248, 81, 73, 0.2)';
        reportList.appendChild(li);
    }
}

function renderChart(score, colorCode) {
    const ctx = document.getElementById('riskChart').getContext('2d');
        if (riskChartInstance) {
        riskChartInstance.destroy();
    }

    const safeScore = 100 - score;

    riskChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Risk', 'Safety'],
            datasets: [{
                data: [score, safeScore],
                backgroundColor: [
                    colorCode, 
                    'rgba(48, 54, 61, 0.3)' 
                ],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            cutout: '80%', 
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            },
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    });
}
const canvas = document.getElementById('matrixCanvas');
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()';
const fontSize = 14;
const columns = canvas.width / fontSize;
const drops = [];

for (let x = 0; x < columns; x++) {
    drops[x] = 1;
}

function drawMatrix() {
    ctx.fillStyle = 'rgba(5, 11, 20, 0.08)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = '#0F0';
    ctx.font = fontSize + 'px monospace';

    for (let i = 0; i < drops.length; i++) {
        const text = chars.charAt(Math.floor(Math.random() * chars.length));
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
            drops[i] = 0;
        }
        drops[i]++;
    }
}

window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});

setInterval(drawMatrix, 33);