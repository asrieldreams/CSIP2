document.getElementById('reportBtn').addEventListener('click', async () => {
  try {
    // 1. Get the URL of the current active browser tab
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    let currentUrl = tab.url;

    // 2. Send the properly structured payload to the Flask backend
    const response = await fetch('http://localhost:5000/report', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json' 
      },
      body: JSON.stringify({
        indicator_type: 'url',
        indicator: currentUrl,
        scam_type: 'Others', // Exact match for the database ENUM
        description: 'Reported via Scam Reporter Shield Extension.', 
        source: 'extension'  // Exact match for the database ENUM
      })
    });

    const result = await response.json();

    if (response.ok) {
      alert("Success: " + result.message);
    } else {
      alert("Error from server: " + (result.error || "Submission failed"));
    }

  } catch (error) {
    console.error("Connection error:", error);
    alert("Could not connect to the backend server. Is it running on port 5000?");
  }
});
