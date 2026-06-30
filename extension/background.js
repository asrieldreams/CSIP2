// Listen for when a user switches tabs or updates a URL
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Skip internal browser pages like chrome://
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('about:')) return;

    // Call Kaden's backend to check if this URL is blacklisted
    fetch(`http://localhost:5000/check?url=${encodeURIComponent(tab.url)}`)
      .then(response => response.json())
      .then(data => {
        if (data.status === 'blacklist') {
          // BLOCK THE PAGE: Redirect the user to a safe warning message
          chrome.tabs.update(tabId, {
            url: 'data:text/html,<html><body style="font-family:Arial;text-align:center;padding-top:100px;background-color:#ffe6e6;color:#cc0000;"><h1>🚨 SCAM ALERT </h1><h2>This website has been blocked by Scam Reporter Shield.</h2><p>Our database confirmed this site is a verified threat.</p></body></html>'
          });
        }
      })
      .catch(err => console.log("Backend not running or unreachable:", err));
  }
});