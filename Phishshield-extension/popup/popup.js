document.addEventListener('DOMContentLoaded', function() {
  const status = document.getElementById('status');
  const urlElement = document.getElementById('url');
  const details = document.getElementById('details');
  const scoreElement = document.getElementById('score');
  const scoreBarFill = document.getElementById('score-bar-fill');
  const reasonElement = document.getElementById('reason');
  const reportBtn = document.getElementById('reportBtn');
  const optionsBtn = document.getElementById('optionsBtn');
  const moreDetailsBtn = document.getElementById('moreDetailsBtn');
  const advancedDetails = document.getElementById('advancedDetails');
  const advancedDetailsContent = document.getElementById('advancedDetailsContent');
  
  // Get domain from the current in use tab
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (tabs[0]) {
      const currentUrl = tabs[0].url;
      urlElement.textContent = currentUrl;
      
      // Here we can look at URL through background script
      chrome.runtime.sendMessage(
        { type: 'checkUrl', url: currentUrl }, 
        function(response) {
          if (response && response.status === 'checking') {
            status.textContent = 'Analyzing page...';
          }
        }
      );
    }
  });
  
  // Open advanced details
  moreDetailsBtn.addEventListener('click', function() {
    if (advancedDetails.style.display === 'none') {
      advancedDetails.style.display = 'block';
      moreDetailsBtn.textContent = 'Hide Advanced Details';
    } else {
      advancedDetails.style.display = 'none';
      moreDetailsBtn.textContent = 'Show Advanced Details';
    }
  });
  
  // listen the results from background script
  chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.type === 'urlChecked') {
      const { url, result } = request.data;
      
      // Update UI based on result with proper status messages
      if (result.isPhishing) {
        status.textContent = '🚨 PHISHING DETECTED';
        status.className = 'status danger';
      } else if (result.score > 50) {
        status.textContent = '⚠️ SUSPICIOUS PAGE';
        status.className = 'status warning';
      } else if (result.score > 30) {
        status.textContent = '⚠️ LOW RISK DETECTED';
        status.className = 'status warning';
      } else {
        status.textContent = '✅ PAGE IS SAFE';
        status.className = 'status safe';
      }
      
      details.style.display = 'block';
      scoreElement.textContent = result.score.toFixed(2) + '/100';
      reasonElement.textContent = result.reason;
      
      // Maintain the score bar
      scoreBarFill.style.width = result.score + '%';
      if (result.score < 30) {
        scoreBarFill.className = 'score-fill score-low';
      } else if (result.score < 70) {
        scoreBarFill.className = 'score-fill score-medium';
      } else {
        scoreBarFill.className = 'score-fill score-high';
      }
      
      // Show advanced details at button push
      if (result.details) {
        let detailsHtml = '';
        if (result.details.heuristicScore !== undefined) {
          detailsHtml += `<p><span class="label">URL Analysis:</span> <span class="value">${result.details.heuristicScore}/100</span></p>`;
        }
        if (result.details.certScore !== undefined) {
          detailsHtml += `<p><span class="label">Certificate Analysis:</span> <span class="value">${result.details.certScore}/100</span></p>`;
        }
        if (result.details.mlScore !== undefined) {
          detailsHtml += `<p><span class="label">ML Analysis:</span> <span class="value">${result.details.mlScore.toFixed(2)}/100</span></p>`;
        }
        if (result.details.cookieScore !== undefined) {
          detailsHtml += `<p><span class="label">Cookie Analysis:</span> <span class="value">${result.details.cookieScore}/100</span></p>`;
        }
        advancedDetailsContent.innerHTML = detailsHtml;
        moreDetailsBtn.style.display = 'block';
      }
      
      if (!result.isPhishing) {
        reportBtn.style.display = 'block';
      }
    }
  });
  
  // Report false positive
  reportBtn.addEventListener('click', function() {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      if (tabs[0]) {
        chrome.runtime.sendMessage(
          { type: 'reportPhishing', url: tabs[0].url },
          function(response) {
            if (response && response.status === 'reported') {
              reportBtn.textContent = 'Reported!';
              reportBtn.disabled = true;
            }
          }
        );
      }
    });
  });
  
  // Open options page
  optionsBtn.addEventListener('click', function() {
    chrome.runtime.openOptionsPage();
  });
});