// ChainSentinel — Frontend App Logic v2 (with API Key + Payment)

const API_BASE = window.location.origin;

const form = document.getElementById('check-form');
const addressInput = document.getElementById('address-input');
const chainSelect = document.getElementById('chain-select');
const apiKeyInput = document.getElementById('api-key-input');
const checkBtn = document.getElementById('check-btn');
const resultDiv = document.getElementById('result');
const loadingDiv = document.getElementById('loading');
const errorDiv = document.getElementById('error');

// Payment verification
const verifyForm = document.getElementById('verify-form');
const txHashInput = document.getElementById('tx-hash-input');
const paymentChain = document.getElementById('payment-chain');
const paymentPlan = document.getElementById('payment-plan');
const emailInput = document.getElementById('email-input');
const verifyBtn = document.getElementById('verify-btn');
const verifyResult = document.getElementById('verify-result');
const verifyLoading = document.getElementById('verify-loading');
const verifyError = document.getElementById('verify-error');

// Risk color mapping
const riskColors = {
    low: '#00b894',
    medium: '#fdcb6e',
    high: '#e17055',
    critical: '#d63031',
};

// --- Address Check ---

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const address = addressInput.value.trim();
    const chain = chainSelect.value;
    const apiKey = apiKeyInput.value.trim();

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
        const headers = { 'Content-Type': 'application/json' };
        if (apiKey) {
            headers['X-API-Key'] = apiKey;
        }

        const resp = await fetch(`${API_BASE}/api/v1/check`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ address, chain }),
        });

        if (!resp.ok) {
            const err = await resp.json();
            if (resp.status === 429) {
                throw new Error('Free tier limit reached (3 checks/day). Upgrade to Pro for unlimited AI analysis.');
            }
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

    // Tier badge
    const tierBadge = document.getElementById('tier-badge');
    if (data.tier === 'pro') {
        tierBadge.textContent = '⚡ Pro AI Analysis';
        tierBadge.className = 'tier-badge pro';
    } else {
        tierBadge.textContent = '🆓 Free (Rule-based)';
        tierBadge.className = 'tier-badge free';
    }

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

    // Show upgrade CTA for free tier
    const upgradeCta = document.getElementById('upgrade-cta');
    if (data.tier === 'free') {
        upgradeCta.style.display = 'block';
    } else {
        upgradeCta.style.display = 'none';
    }
}

function showError(msg) {
    errorDiv.style.display = 'block';
    errorDiv.textContent = msg;
}

// --- Payment Verification ---

verifyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const tx_hash = txHashInput.value.trim();
    const chain = paymentChain.value;
    const plan = paymentPlan.value;
    const email = emailInput.value.trim();

    if (!tx_hash || tx_hash.length < 10) {
        showVerifyError('Please enter a valid transaction hash.');
        return;
    }

    verifyResult.style.display = 'none';
    verifyError.style.display = 'none';
    verifyLoading.style.display = 'block';
    verifyBtn.disabled = true;
    verifyBtn.textContent = 'Verifying...';

    try {
        const resp = await fetch(`${API_BASE}/api/v1/verify-payment`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tx_hash, chain, plan, email }),
        });

        if (!resp.ok) {
            const err = await resp.json();
            throw new Error(err.detail || 'Verification failed');
        }

        const data = await resp.json();
        showVerifyResult(data);
    } catch (err) {
        showVerifyError(err.message || 'Verification error. Please try again.');
    } finally {
        verifyLoading.style.display = 'none';
        verifyBtn.disabled = false;
        verifyBtn.textContent = '🔑 Verify & Get API Key';
    }
});

function showVerifyResult(data) {
    verifyResult.style.display = 'block';
    verifyResult.innerHTML = `
        <div class="success-box">
            <h4>✅ API Key Activated!</h4>
            <p>Plan: <strong>${data.plan.toUpperCase()}</strong> · Expires: ${new Date(data.expires_at).toLocaleDateString()}</p>
            <div class="api-key-box">
                <code>${data.api_key}</code>
                <button class="copy-btn" onclick="copyApiKey('${data.api_key}')">📋</button>
            </div>
            <p class="key-usage">Use this key as <code>X-API-Key</code> header in your API requests, or paste it in the check form above.</p>
        </div>
    `;
    // Auto-fill the API key input
    apiKeyInput.value = data.api_key;
}

function showVerifyError(msg) {
    verifyError.style.display = 'block';
    verifyError.textContent = msg;
}

// --- Utility ---

function copyWallet() {
    const wallet = document.getElementById('wallet-address').textContent;
    navigator.clipboard.writeText(wallet).then(() => {
        const btn = document.querySelector('.wallet-box .copy-btn');
        btn.textContent = '✅';
        setTimeout(() => btn.textContent = '📋', 2000);
    });
}

function copyApiKey(key) {
    navigator.clipboard.writeText(key).then(() => {
        // brief feedback
    });
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

// Load pricing info
async function loadPricing() {
    try {
        const resp = await fetch(`${API_BASE}/api/v1/pricing`);
        if (resp.ok) {
            const data = await resp.json();
            document.getElementById('wallet-address').textContent = data.wallet_address;
        }
    } catch {}
}
loadPricing();
