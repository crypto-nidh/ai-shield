const DEFAULT_API_URL = "http://localhost:8000";

// Restores select box and checkbox state using the preferences stored in chrome.storage.
function restoreOptions() {
  chrome.storage.sync.get({
    apiBaseUrl: DEFAULT_API_URL
  }, function(items) {
    document.getElementById('api-url').value = items.apiBaseUrl;
  });
}

// Saves options to chrome.storage
function saveOptions() {
  let apiUrl = document.getElementById('api-url').value.trim();
  
  // Remove trailing slash if present
  if (apiUrl.endsWith('/')) {
    apiUrl = apiUrl.slice(0, -1);
  }

  chrome.storage.sync.set({
    apiBaseUrl: apiUrl || DEFAULT_API_URL
  }, function() {
    // Update status to let user know options were saved.
    const status = document.getElementById('status');
    status.style.display = 'block';
    setTimeout(function() {
      status.style.display = 'none';
    }, 2000);
  });
}

document.addEventListener('DOMContentLoaded', restoreOptions);
document.getElementById('save-btn').addEventListener('click', saveOptions);
