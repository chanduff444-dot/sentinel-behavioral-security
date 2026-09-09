// Load and display threats
chrome.storage.local.get({threats: []}, (result) => {
  const threatList = document.getElementById('threatList');
  
  if (result.threats.length === 0) {
    threatList.innerHTML = '<div class="no-threats">No threats detected yet</div>';
  } else {
    threatList.innerHTML = result.threats.reverse().map(threat => `
      <div class="threat-item">
        <div class="threat-url">${threat.url}</div>
        <div class="threat-type">⚠️ ${threat.threat_type} (${threat.confidence}%)</div>
        <div class="threat-time">${new Date(threat.timestamp).toLocaleString()}</div>
      </div>
    `).join('');
  }
});

// Clear history
document.getElementById('clearBtn').addEventListener('click', () => {
  chrome.storage.local.set({threats: []}, () => {
    location.reload();
  });
});
