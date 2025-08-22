// Background service worker for real-time URL analysis
class PhishShield {
  constructor() {
    this.blacklist = new Set();
    this.cache = new Map();
    
    this.loadBlacklist = this.loadBlacklist.bind(this);
    this.setupListeners = this.setupListeners.bind(this);
    this.checkUrl = this.checkUrl.bind(this);
    this.extractDomain = this.extractDomain.bind(this);
    this.heuristicCheck = this.heuristicCheck.bind(this);
    this.analyzeCertificate = this.analyzeCertificate.bind(this);
    this.mlCheck = this.mlCheck.bind(this);
    this.handleResult = this.handleResult.bind(this);
    this.updateBlacklistFromAPI = this.updateBlacklistFromAPI.bind(this);
    this.analyzeCookieBehavior = this.analyzeCookieBehavior.bind(this);
    
    this.loadBlacklist();
    this.setupListeners();
  }

  async loadBlacklist() {
    try {
      const result = await chrome.storage.local.get(['phishShieldBlacklist']);
      if (result.phishShieldBlacklist) {
        this.blacklist = new Set(result.phishShieldBlacklist);
      }
    } catch (error) {
      console.error('Failed to load blacklist:', error);
    }
  }

  setupListeners() {
    // Check URLs on tab updates
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        this.checkUrl(tab.url, tabId);
      }
    });

    // Periodically we need to update blacklist
    chrome.alarms.create('updateBlacklist', { periodInMinutes: 60 });
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === 'updateBlacklist') {
        this.updateBlacklistFromAPI();
      }
    });
  }

  async checkUrl(url, tabId) {
    // Check site cache first
    if (this.cache.has(url)) {
      const result = this.cache.get(url);
      this.handleResult(result, tabId, url);
      return;
    }

    // Check blacklist 
    const domain = this.extractDomain(url);
    if (this.blacklist.has(domain)) {
      this.handleResult({ isPhishing: true, score: 100, reason: 'Blacklisted domain' }, tabId, url);
      return;
    }

    // Check URL patterns heuristically
    const heuristicScore = this.heuristicCheck(url);
    
    // Check SSL/TLS certificate
    const certScore = await this.analyzeCertificate(url);
    
    // ML analysis
    const mlScore = await this.mlCheck(url);
    
    // Combine scores with weights
    const finalScore = Math.min(
      heuristicScore + certScore * 0.7 + mlScore * 0.8,
      100
    );
    
    const reasons = [];
    if (heuristicScore > 40) reasons.push('Suspicious URL pattern');
    if (certScore > 30) reasons.push('Certificate issues detected');
    if (mlScore > 35) reasons.push('ML analysis indicates risk');
    
    const result = {
      isPhishing: finalScore > 65, // Lowered threshold from 70 to 65
      score: finalScore,
      reason: reasons.length > 0 ? reasons.join(', ') : 'Likely safe',
      details: {
        heuristicScore,
        certScore,
        mlScore
      }
    };
    
    this.cache.set(url, result);
    this.handleResult(result, tabId, url);
    
    // Analyze cookie behavior after page loads
    setTimeout(() => {
      this.analyzeCookieBehavior(tabId, url);
    }, 2000);
  }

  extractDomain(url) {
    try {
      const domain = new URL(url).hostname;
      return domain.replace(/^www\./, '');
    } catch {
      return url;
    }
  }

  heuristicCheck(url) {
    let score = 0;
    const domain = this.extractDomain(url);
    const fullUrl = url.toLowerCase();
    
    // 1. Domain impersonation detection
    const popularDomains = [
      'paypal', 'google', 'facebook', 'amazon', 'apple', 
      'microsoft', 'netflix', 'bankofamerica', 'wellsfargo',
      'chase', 'citibank', 'linkedin', 'twitter', 'instagram'
    ];
    
    popularDomains.forEach(popDomain => {
      if (domain.includes(popDomain)) {
        // Check if it's not the actual domain
        if (!domain.endsWith(popDomain + '.com') && 
            !domain.endsWith(popDomain + '.org') &&
            !domain.endsWith(popDomain + '.net')) {
          score += 35;
        }
      }
    });
    
    // 2. Suspicious keyword detection with higher weights
    const phishingKeywords = [
      {keyword: 'login', score: 15},
      {keyword: 'verify', score: 20},
      {keyword: 'account', score: 15},
      {keyword: 'secure', score: 15},
      {keyword: 'banking', score: 25},
      {keyword: 'update', score: 20},
      {keyword: 'signin', score: 15},
      {keyword: 'security', score: 20},
      {keyword: 'validation', score: 20},
      {keyword: 'confirm', score: 15},
      {keyword: 'billing', score: 20}
    ];
    
    phishingKeywords.forEach(item => {
      if (domain.includes(item.keyword) || fullUrl.includes(item.keyword)) {
        score += item.score;
      }
    });
    
    // 3. Suspicious extension detection
    const suspiciousTlds = ['.xyz', '.top', '.club', '.loan', '.tk', '.ml', '.ga', '.cf'];
    suspiciousTlds.forEach(tld => {
      if (domain.endsWith(tld)) {
        score += 20;
      }
    });
    
    // 4. Hyphen and special character detection
    const hyphenCount = (domain.match(/-/g) || []).length;
    if (hyphenCount > 2) {
      score += 25;
    } else if (hyphenCount > 0) {
      score += 10;
    }
    
    // 5. Domain length (long domains links are suspicious)
    if (domain.length > 35) {
      score += 15;
    } else if (domain.length > 25) {
      score += 10;
    }
    
    // 6. IP address instead of domain
    if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
      score += 30;
    }
    
    // 7. Subdomain count (large no. of subdomains are suspicious)
    const subdomainCount = (domain.match(/\./g) || []).length;
    if (subdomainCount > 3) {
      score += 20;
    } else if (subdomainCount > 2) {
      score += 10;
    }
    
    // 8. Specific pattern detection for likely phishing patterns
    const phishingPatterns = [
      /paypal.*security.*verification/,
      /bank.*login.*secure/,
      /verify.*account.*update/,
      /secure.*login.*portal/,
      /identity.*verification.*required/
    ];
    
    phishingPatterns.forEach(pattern => {
      if (pattern.test(fullUrl)) {
        score += 40;
      }
    });
    
    return Math.min(score, 100);
  }

  async analyzeCertificate(url) {
    let score = 0;
    const reasons = [];
    
    try {
      // Check if HTTPS
      if (!url.startsWith('https://')) {
        score += 50;
        reasons.push('Not using HTTPS');
      } else {
        const domain = this.extractDomain(url);
        
        // Simulate more detailed certificate analysis
        
        // Check if certificate is from a free CA (more common for phishing)
        const freeCAs = ['Let\'s Encrypt', 'ZeroSSL', 'SSL.com', 'cPanel', 'Cloudflare'];
        const isFreeCA = Math.random() > 0.6; // 40% chance for demo
        
        if (isFreeCA) {
          score += 25;
          reasons.push('Certificate from free CA');
        }
        
        // Check if certificate is very new (less than 3 days old)
        const isNewCert = Math.random() > 0.7; // 30% chance for demo
        if (isNewCert) {
          score += 10;
          reasons.push('Very new certificate (< 3 days)');
        }
        
        // Check if certificate is about to expire (less than 7 days)
        const isExpiring = Math.random() > 0.9; // 10% chance for demo
        if (isExpiring) {
          score += 15;
          reasons.push('Certificate expiring soon (< 7 days)');
        }
        
        // Check for domain mismatch
        const hasMismatch = Math.random() > 0.8; // 20% chance for demo
        if (hasMismatch) {
          score += 40;
          reasons.push('Certificate domain mismatch');
        }
      }
    } catch (error) {
      console.error('Certificate analysis failed:', error);
    }
    
    return Math.min(score, 100);
  }

  async mlCheck(url) {
    try {
      // Simulate a more sophisticated ML model
      const domain = this.extractDomain(url);
      
      // Base score from URL features
      let mlScore = Math.random() * 30;
      
      // Add more points for suspicious patterns
      if (domain.includes('paypal') || domain.includes('bank')) {
        mlScore += 25;
      }
      
      if (domain.includes('verify') || domain.includes('security')) {
        mlScore += 20;
      }
      
      if (domain.includes('login') || domain.includes('signin')) {
        mlScore += 15;
      }
      
      // Add points for suspicious extensions
      const suspiciousTlds = ['.xyz', '.top', '.club', '.loan', '.tk', '.ml', '.ga', '.cf'];
      if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
        mlScore += 25;
      }
      
      // Add points for hyphens
      const hyphenCount = (domain.match(/-/g) || []).length;
      if (hyphenCount > 0) {
        mlScore += (hyphenCount * 5);
      }
      
      return Math.min(mlScore, 100);
    } catch (error) {
      console.error('ML check failed:', error);
      return 0;
    }
  }

  handleResult(result, tabId, url) {
    if (result.isPhishing) {
      // Store the result for the content script to display warning
      chrome.storage.local.set({ [`phishShield_${tabId}`]: result });
      
      // Update extension badge
      chrome.action.setBadgeText({ tabId, text: '!' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#FF0000' });
      
      // Show notification for high-risk sites
      if (result.score > 85) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon48.png',
          title: 'Phishing Warning',
          message: `PhishShield blocked a potential phishing site: ${this.extractDomain(url)}`
        });
      }
      
      // Send message to content script to show warning
      this.sendMessageToTab(tabId, { type: 'showWarning', data: result });
    } else {
      // Set appropriate badge based on score
      if (result.score > 30) {
        chrome.action.setBadgeText({ tabId, text: '?' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#FF9900' });
      } else {
        chrome.action.setBadgeText({ tabId, text: '' });
      }
    }
    
    // Send message to popup if it's open (with error handling)
    this.sendMessageToPopup({ type: 'urlChecked', data: { url, result } });
  }
  
  // Safe method to send messages to tabs
  sendMessageToTab(tabId, message) {
    chrome.tabs.sendMessage(tabId, message).catch(error => {
      // This is normal if the content script isn't injected yet
      console.log('Content script not ready:', error);
    });
  }
  
  // Safe method to send messages to popup
  sendMessageToPopup(message) {
    chrome.runtime.sendMessage(message).catch(error => {
      // This is normal if the popup isn't open
      console.log('Popup not open:', error);
    });
  }

  async analyzeCookieBehavior(tabId, url) {
    try {
      // Execute script in the tab to analyze cookie behavior
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        func: () => {
          // Count cookies
          const cookieCount = document.cookie.split(';').filter(c => c.trim()).length;
          
          // Check for HttpOnly cookies
          const httpOnlyCookies = document.cookie.split(';').filter(c => 
            c.includes('HttpOnly') || c.includes('httponly')
          ).length;
          
          // Check for Secure cookies
          const secureCookies = document.cookie.split(';').filter(c => 
            c.includes('Secure') || c.includes('secure')
          ).length;
          
          // Look for tracking cookies
          const trackingKeywords = ['_ga', '_gid', 'fbp', 'fbc', '_gat'];
          const trackingCookies = document.cookie.split(';').filter(c => 
            trackingKeywords.some(keyword => c.includes(keyword))
          ).length;
          
          return {
            cookieCount,
            httpOnlyCookies,
            secureCookies,
            trackingCookies
          };
        }
      });
      
      if (results && results[0] && results[0].result) {
        const cookieData = results[0].result;
        
        // Analyze cookie behavior
        let cookieScore = 0;
        const cookieReasons = [];
        
        // Many cookies but few secure/HttpOnly is suspicious
        if (cookieData.cookieCount > 5 && cookieData.secureCookies < cookieData.cookieCount * 0.3) {
          cookieScore += 25;
          cookieReasons.push('Lack of secure cookies');
        }
        
        if (cookieData.cookieCount > 8 && cookieData.httpOnlyCookies < cookieData.cookieCount * 0.3) {
          cookieScore += 25;
          cookieReasons.push('Lack of HttpOnly cookies');
        }
        
        // Excessive tracking cookies
        if (cookieData.trackingCookies > 3) {
          cookieScore += 15;
          cookieReasons.push('Excessive tracking cookies');
        }
        
        // Update the result if cookie analysis found issues
        if (cookieScore > 20) {
          const key = `phishShield_${tabId}`;
          chrome.storage.local.get([key], (data) => {
            if (data[key]) {
              const existingResult = data[key];
              const newScore = Math.min(existingResult.score + cookieScore, 100);
              
              const updatedResult = {
                ...existingResult,
                score: newScore,
                reason: existingResult.reason + (cookieReasons.length > 0 ? ', ' + cookieReasons.join(', ') : ''),
                details: {
                  ...existingResult.details,
                  cookieScore
                }
              };
              
              // Update the stored result
              chrome.storage.local.set({ [key]: updatedResult });
              
              // Update badge if needed
              if (newScore > 65 && !existingResult.isPhishing) {
                chrome.action.setBadgeText({ tabId, text: '!' });
                chrome.action.setBadgeBackgroundColor({ tabId, color: '#FF0000' });
              }
            }
          });
        }
      }
    } catch (error) {
      // This is normal if the page doesn't allow scripting or has restrictive CSP
      console.log('Cookie analysis not possible:', error);
    }
  }

  async updateBlacklistFromAPI() {
    try {
      // This would fetch from a blacklist API like VirusTotal or PhishTank
      // For demo, we'll use a static list that gets updated occasionally
      const response = await fetch('https://openphish.com/feed.txt');
      const text = await response.text();
      const newBlacklist = text.split('\n').filter(line => line.trim() !== '');
      
      this.blacklist = new Set([...this.blacklist, ...newBlacklist]);
      chrome.storage.local.set({ phishShieldBlacklist: Array.from(this.blacklist) });
      
      // Update last updated time
      chrome.storage.local.set({ blacklistLastUpdated: Date.now() });
    } catch (error) {
      console.error('Failed to update blacklist:', error);
    }
  }
}

// Initialize the extension
let phishShield;

// Handle extension startup
chrome.runtime.onStartup.addListener(() => {
  phishShield = new PhishShield();
});

// Handle extension installation
chrome.runtime.onInstalled.addListener(() => {
  phishShield = new PhishShield();
});

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (!phishShield) {
    phishShield = new PhishShield();
  }
  
  // Check if sender.tab exists before accessing its properties
  const tabId = sender && sender.tab ? sender.tab.id : null;
  
  if (request.type === 'checkUrl') {
    // If we have a tabId from the sender, use it, otherwise try to get current tab
    if (tabId) {
      phishShield.checkUrl(request.url, tabId);
    } else {
      // Fallback: try to get the current active tab
      chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
        if (tabs[0]) {
          phishShield.checkUrl(request.url, tabs[0].id);
        }
      });
    }
    sendResponse({ status: 'checking' });
  } else if (request.type === 'reportPhishing') {
    // Add to blacklist and update
    phishShield.blacklist.add(phishShield.extractDomain(request.url));
    chrome.storage.local.set({ phishShieldBlacklist: Array.from(phishShield.blacklist) });
    sendResponse({ status: 'reported' });
  } else if (request.type === 'getCurrentTabId') {
    // Return the tab ID if available
    if (tabId) {
      sendResponse({tabId: tabId});
    } else {
      // Fallback: try to get the current active tab
      chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
        if (tabs[0]) {
          sendResponse({tabId: tabs[0].id});
        } else {
          sendResponse({tabId: null});
        }
      });
      return true; // Indicates we'll respond asynchronously
    }
  } else if (request.type === 'analyzeCertificate') {
    // Analyze certificate for a URL
    phishShield.analyzeCertificate(request.url).then(score => {
      sendResponse({ score });
    });
    return true; // Async response
  }
  return true; // Keeps the message channel open for async response
});