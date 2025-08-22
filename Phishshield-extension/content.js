// Content script to display warnings on phishing pages

// Enhanced page content analysis
function analyzePageContent() {
  const phishingIndicators = {
    loginForms: 0,
    passwordFields: 0,
    financialKeywords: 0,
    urgencyIndicators: 0,
    copycatElements: 0
  };
  
  // Check for login forms
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    const html = form.innerHTML.toLowerCase();
    if (html.includes('password') || html.includes('login') || html.includes('signin')) {
      phishingIndicators.loginForms++;
    }
  });
  
  // Check for password fields
  const passwordFields = document.querySelectorAll('input[type="password"]');
  phishingIndicators.passwordFields = passwordFields.length;
  
  // Check for financial keywords
  const financialKeywords = [
    'bank', 'account', 'login', 'password', 'verify', 'security',
    'payment', 'credit', 'card', 'paypal', 'social security'
  ];
  
  const bodyText = document.body.innerText.toLowerCase();
  financialKeywords.forEach(keyword => {
    if (bodyText.includes(keyword)) {
      phishingIndicators.financialKeywords++;
    }
  });
  
  // Check for urgency indicators
  const urgencyPhrases = [
    'urgent', 'immediately', 'action required', 'verify now',
    'security alert', 'suspended', 'locked', 'limited time'
  ];
  
  urgencyPhrases.forEach(phrase => {
    if (bodyText.includes(phrase)) {
      phishingIndicators.urgencyIndicators++;
    }
  });
  
  // Check for copycat elements (logos, brands)
  const brandNames = ['paypal', 'google', 'facebook', 'amazon', 'apple', 'microsoft'];
  brandNames.forEach(brand => {
    const logos = document.querySelectorAll(`img[src*="${brand}"], img[alt*="${brand}"]`);
    if (logos.length > 0) {
      phishingIndicators.copycatElements++;
    }
  });
  
  return phishingIndicators;
}

// Enhanced cookie analysis
function analyzeCookies() {
  const cookies = document.cookie.split(';');
  const cookieAnalysis = {
    total: cookies.length,
    secure: 0,
    httpOnly: 0,
    session: 0,
    persistent: 0,
    thirdParty: 0
  };
  
  cookies.forEach(cookie => {
    const cookieStr = cookie.trim();
    
    if (cookieStr.includes('Secure')) cookieAnalysis.secure++;
    if (cookieStr.includes('HttpOnly')) cookieAnalysis.httpOnly++;
    if (cookieStr.includes('Expires') || cookieStr.includes('Max-Age')) {
      cookieAnalysis.persistent++;
    } else {
      cookieAnalysis.session++;
    }
    
    // Simple third-party detection (could be enhanced)
    if (cookieStr.includes('google') || cookieStr.includes('facebook') || 
        cookieStr.includes('doubleclick') || cookieStr.includes('analytics')) {
      cookieAnalysis.thirdParty++;
    }
  });
  
  return cookieAnalysis;
}

// Send page analysis to background script
function sendPageAnalysis() {
  const pageIndicators = analyzePageContent();
  const cookieAnalysis = analyzeCookies();
  
  chrome.runtime.sendMessage({
    type: 'pageAnalysis',
    data: {
      url: window.location.href,
      pageIndicators,
      cookieAnalysis
    }
  });
}

// Run analysis when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', sendPageAnalysis);
} else {
  sendPageAnalysis();
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'showWarning') {
    showWarning(request.data);
  }
});

// Function to show warning overlay
function showWarning(result) {
  // Don't show multiple warnings
  if (document.getElementById('phishshield-warning')) {
    return;
  }
  
  // Create warning overlay
  const overlay = document.createElement('div');
  overlay.id = 'phishshield-warning';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.8);
    z-index: 9999;
    display: flex;
    justify-content: center;
    align-items: center;
    font-family: Arial, sans-serif;
  `;
  
  const warningBox = document.createElement('div');
  warningBox.style.cssText = `
    background: white;
    padding: 30px;
    border-radius: 10px;
    text-align: center;
    max-width: 500px;
    box-shadow: 0 0 20px rgba(255,0,0,0.5);
  `;
  
  const title = document.createElement('h2');
  title.textContent = '⚠️ PHISHING WARNING ⚠️';
  title.style.color = '#FF0000';
  
  const score = document.createElement('p');
  score.textContent = `PhishShield detected this site as suspicious (Score: ${result.score}/100)`;
  score.style.fontWeight = 'bold';
  
  const reason = document.createElement('p');
  reason.textContent = `Reason: ${result.reason}`;
  reason.style.marginBottom = '20px';
  
  const continueButton = document.createElement('button');
  continueButton.textContent = 'I understand the risks, continue anyway';
  continueButton.style.cssText = `
    background: #FF9900;
    color: white;
    border: none;
    padding: 10px 15px;
    border-radius: 5px;
    cursor: pointer;
    margin-right: 10px;
  `;
  continueButton.onclick = () => {
    overlay.remove();
    chrome.runtime.sendMessage({ 
      type: 'userOverride', 
      url: window.location.href 
    });
  };
  
  const backButton = document.createElement('button');
  backButton.textContent = 'Take me to safety';
  backButton.style.cssText = `
    background: #4CAF50;
    color: white;
    border: none;
    padding: 10px 15px;
    border-radius: 5px;
    cursor: pointer;
  `;
  backButton.onclick = () => {
    window.location.href = 'https://www.google.com';
  };
  
  warningBox.appendChild(title);
  warningBox.appendChild(score);
  warningBox.appendChild(reason);
  warningBox.appendChild(continueButton);
  warningBox.appendChild(backButton);
  overlay.appendChild(warningBox);
  
  document.body.appendChild(overlay);
  document.body.style.overflow = 'hidden';
}

// Check if this page was already flagged when the content script loads
// Using URL-based storage instead of tab-based
const currentUrl = window.location.href;
chrome.storage.local.get(['phishShieldResults'], (result) => {
  if (result.phishShieldResults && result.phishShieldResults[currentUrl]) {
    const phishingResult = result.phishShieldResults[currentUrl];
    if (phishingResult.isPhishing) {
      showWarning(phishingResult);
    }
  }
});