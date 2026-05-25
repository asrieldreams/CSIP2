document.getElementById('reportBtn').addEventListener('click', async () => {
  // 1. Get the URL of the current active browser tab
  let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let currentUrl = tab.url;

  // 2. Send this URL to your backend (Replace with your actual backend URL later)
  alert("Reporting: " + currentUrl); 
  
  /* Eventually, you will replace the alert above with code like this:
  
  fetch('http://localhost:5000/api/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: currentUrl })
  });
  */
});