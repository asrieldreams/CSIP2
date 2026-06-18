document.getElementById('reportBtn').addEventListener('click', async () => {
  const statusMessage = document.getElementById('statusMessage') || document.createElement('p');
  
  try {
    // 1. Get the URL of the current active browser tab
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    let currentUrl = tab.url;

    // Optional: basic visual feedback for the user
    statusMessage.innerText = "Sending report...";
    statusMessage.style.color = "blue";

    // 2. Send the properly structured payload to Kaden's Flask backend
    const response = await fetch('http://localhost:5000/report', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json' 
      },
      body: JSON.stringify({
        indicator_type: 'url',        // Tells backend this is a website URL
        indicator: currentUrl,         // The actual URL grabbed from the tab
        scam_type: 'Others',           // Default classification required by backend
        description: 'Reported via Scam Reporter Shield Extension.', 
        source: 'extension'            // Identifies that this came from your folder!
      })
    });

    const result = await response.json();

    // 3. Handle the response
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
