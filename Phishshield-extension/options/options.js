document.addEventListener('DOMContentLoaded', function() {
  // We Load saved settings
  chrome.storage.local.get([
    'realTimeProtection', 
    'autoBlock', 
    'warnMediumRisk',
    'blacklistLastUpdated'
  ], function(settings) {
    document.getElementById('realTimeProtection').checked = settings.realTimeProtection !== false;
    document.getElementById('autoBlock').checked = settings.autoBlock !== false;
    document.getElementById('warnMediumRisk').checked = settings.warnMediumRisk !== false;
    
    if (settings.blacklistLastUpdated) {
      document.getElementById('lastUpdated').textContent = new Date(settings.blacklistLastUpdated).toLocaleString();
    } else {
      document.getElementById('lastUpdated').textContent = 'Never';
    }
  });
  
  // Setting must be changed here
  document.getElementById('realTimeProtection').addEventListener('change', function() {
    chrome.storage.local.set({ realTimeProtection: this.checked });
  });
  
  document.getElementById('autoBlock').addEventListener('change', function() {
    chrome.storage.local.set({ autoBlock: this.checked });
  });
  
  document.getElementById('warnMediumRisk').addEventListener('change', function() {
    chrome.storage.local.set({ warnMediumRisk: this.checked });
  });
  
  //  blacklist is updated
  document.getElementById('updateNow').addEventListener('click', function() {
    chrome.runtime.sendMessage({ type: 'updateBlacklist' }, function(response) {
      if (response) {
        document.getElementById('lastUpdated').textContent = new Date().toLocaleString();
        chrome.storage.local.set({ blacklistLastUpdated: Date.now() });
      }
    });
  });
  
  // We can see statistics of our extension
  document.getElementById('viewStats').addEventListener('click', function() {
    chrome.tabs.create({ url: chrome.runtime.getURL('options/stats.html') });
  });
});