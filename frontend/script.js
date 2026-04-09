const urlForm = document.getElementById('url-form');
const urlInput = document.getElementById('url-input');
const errorMessage = document.getElementById('error-message');
const resultCard = document.getElementById('result-card');
const resultStatus = document.getElementById('result-status');
const riskBadge = document.getElementById('risk-badge');
const progressBar = document.getElementById('progress-bar');
const progressLabel = document.getElementById('progress-label');
const resultText = document.getElementById('result-text');
const reasonList = document.getElementById('reason-list');
const spinner = document.getElementById('spinner');

function toggleSpinner(visible) {
  spinner.classList.toggle('hidden', !visible);
}

function displayError(message) {
  errorMessage.textContent = message;
  errorMessage.classList.remove('hidden');
  errorMessage.style.animation = 'none';
  setTimeout(() => {
    errorMessage.style.animation = 'slideInDown 0.4s ease-out';
  }, 10);
}

function clearError() {
  errorMessage.textContent = '';
  errorMessage.classList.add('hidden');
}

function renderResult(data) {
  // Update status
  resultStatus.textContent = data.status;
  
  // Update badge with risk score
  riskBadge.textContent = `${data.risk_score}%`;
  riskBadge.className = 'badge';
  
  // Add color indicator based on risk
  if (data.risk_score >= 70) {
    resultStatus.style.color = 'var(--danger-light)';
  } else if (data.risk_score >= 40) {
    resultStatus.style.color = 'var(--warning-light)';
  } else {
    resultStatus.style.color = 'var(--success-light)';
  }
  
  // Update result text
  resultText.textContent = data.status === 'Phishing'
    ? 'This URL shows suspicious patterns and may be unsafe. Proceed with caution.'
    : 'This URL appears safe based on machine learning analysis. However, always verify links before sharing sensitive information.';
  
  // Show result card
  resultCard.classList.remove('hidden');
  resultCard.style.animation = 'none';
  setTimeout(() => {
    resultCard.style.animation = 'fadeInUp 0.6s ease-out';
  }, 10);

  // Animate progress bar
  progressBar.style.width = '0%';
  setTimeout(() => {
    progressBar.style.width = `${data.risk_score}%`;
  }, 100);
  
  progressLabel.textContent = `${data.risk_score}% risk`;

  // Render reasons list with staggered animation
  if (data.reasons && data.reasons.length > 0) {
    reasonList.innerHTML = data.reasons.map((reason, index) => {
      return `<div class="reason-item" style="animation-delay: ${index * 0.1}s;">${reason}</div>`;
    }).join('');
  } else {
    reasonList.innerHTML = '<div class="reason-item">No major red flags detected.</div>';
  }
}

function renderHistory(rows) {
  // History is now on a separate page, no rendering needed here
}

async function fetchHistory() {
  // History is now on a separate page, no fetching needed here
}

async function checkUrl(url) {
  toggleSpinner(true);
  clearError();
  resultCard.classList.add('hidden');

  try {
    const response = await fetch('/check_url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url.trim() }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || 'Server error');
    }

    renderResult(data);
    
    // Add URL to input history for easy re-checking
    urlInput.value = '';
    urlInput.focus();
  } catch (error) {
    displayError(error.message || 'Something went wrong');
  } finally {
    toggleSpinner(false);
  }
}

urlForm.addEventListener('submit', event => {
  event.preventDefault();
  const urlValue = urlInput.value;
  if (!urlValue) {
    displayError('Please enter a URL before checking.');
    return;
  }

  checkUrl(urlValue);
});

// Focus input on page load for better UX
window.addEventListener('DOMContentLoaded', () => {
  urlInput.focus();
});
