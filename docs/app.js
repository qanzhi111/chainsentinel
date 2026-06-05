// ChainSentinel — Frontend App Logic

// API backend — update after HF Spaces deployment
const API_BASE = 'https://chainsentinel-api.hf.space';

const form = document.getElementById('check-form');
const addressInput = document.getElementById('address-input');
const chainSelect = document.getElementById('chain-select');
const checkBtn = document.getElementById('check-btn');
const resultDiv = document.getElementById('result');
const loadingDiv = document.getElementById('loading');
const errorDiv = document.getElementById('error');

// Risk color mapping
const riskColors = {
    low: '#00b894',
    medium: '#fdcb6e',
    high: '#e17055',
    critical: '#d63031',
};

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const address = addressInput.value.trim();
    const chain = chainSelect.value;

    if (!address || address.length < 10) {
        showError('Please enter a valid address (at least 10 characters).');
        return;
    }

    // UI state
    resultDiv.style.display = 'none';
    errorDiv.style.display = 'none';
    loadingDiv.style.display = 'block';
    checkBtn.disabled = true;
    checkBtn.textContent = 'Scanning...';

    try {
        const resp = await fetch(`${API_BASE}/api/v1/check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ address, chain }),
        });

        if (!resp.ok) {
            const err = await resp.json();
            throw new Error(err.detail || 'Analysis failed');
        }

        const data = await resp.json();
        showResult(data);
    } catch (err) {
        showError(err.message || 'Network error. Please try again.');
    } finally {
        loadingDiv.style.display = 'none';
        checkBtn.disabled = false;
        checkBtn.textContent = '🔍 Scan';
    }
});

function showResult(data) {
    resultDiv.style.display = 'block';

    // Risk gauge
    const score = data.risk_score;
    const gaugeArc = document.getElementById('gauge-arc');
    const circumference = 339.29;
    const offset = circumference - (score / 100) * circumference;
    gaugeArc.style.strokeDashoffset = offset;
    gaugeArc.style.stroke = riskColors[data.risk_level] || '#6c5ce7';
    document.getElementById('gauge-score').textContent = score;
    document.getElementById('gauge-score').style.color = riskColors[data.risk_level];

    // Meta
    const badge = document.getElementById('risk-level-badge');
    badge.textContent = data.risk_level;
    badge.className = `risk-level-badge ${data.risk_level}`;
    document.getElementById('result-address').textContent = data.address;
    document.getElementById('result-chain').textContent = `Chain: ${data.chain.toUpperCase()}`;

    // AI analysis
    document.getElementById('ai-analysis').textContent = data.ai_analysis;

    // Findings
    const findingsDiv = document.getElementById('findings');
    if (data.findings && data.findings.length > 0) {
        findingsDiv.innerHTML = '<h4>Risk Factors Found</h4>' +
            data.findings.map(f => `
                <div class="finding">
                    <span class="finding-severity ${f.severity}">${f.severity}</span>
                    <span class="finding-desc">${f.description}</span>
                </div>
            `).join('');
    } else {
        findingsDiv.innerHTML = '<h4>No significant risk factors detected</h4>';
    }
}

function showError(msg) {
    errorDiv.style.display = 'block';
    errorDiv.textContent = msg;
}

// Load live stats
async function loadStats() {
    try {
        const resp = await fetch(`${API_BASE}/api/v1/stats`);
        if (resp.ok) {
            const data = await resp.json();
            document.getElementById('stat-scanned').textContent = data.addresses_scanned.toLocaleString();
            document.getElementById('stat-threats').textContent = data.threats_detected.toLocaleString();
        }
    } catch {}
}
loadStats();
