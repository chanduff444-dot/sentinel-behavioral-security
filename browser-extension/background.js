// Monitor all tab navigations
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) { // Only main frame
    checkUrlThreat(details.url);
  }
});

// Check URL against threat database
async function checkUrlThreat(url) {
  try {
    const response = await fetch('http://localhost:18000/ioc/check-url', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      },
      params: {
        url: url
      }
    });
    
    const data = await response.json();
    
    if (data.is_malicious) {
      // Show warning notification
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon48.png',
        title: '⚠️ MALICIOUS WEBSITE DETECTED!',
        message: `Threat: ${data.threat_type}\nConfidence: ${data.confidence}%\nURL: ${url.substring(0, 50)}...`,
        priority: 2
      });
      
      // Store in extension storage
      chrome.storage.local.get({threats: []}, (result) => {
        result.threats.push({
          url: url,
          threat_type: data.threat_type,
          confidence: data.confidence,
          timestamp: new Date().toISOString()
        });
        chrome.storage.local.set({threats: result.threats});
      });
    }
  } catch (error) {
    console.error('Error checking URL:', error);
  }
}

// Send URL to backend for logging
async function logUrlVisit(url) {
  try {
    await fetch('http://localhost:18000/events', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user_id: 1,
        event_type: 'website_visit',
        payload: {url: url}
      })
    });
  } catch (error) {
    console.error('Error logging URL:', error);
  }
}
