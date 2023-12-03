// popup.js
document.addEventListener('DOMContentLoaded', function () {
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, function (tabs) {
    let url = tabs[0].url;
    document.getElementById('captured-url').textContent = `Captured URL: ${url}`;

    // Send the URL to your API
    sendUrlToApi(url);
  });

  chrome.runtime.sendMessage({ action: 'getVulnerabilityInfo' }, function (response) {
    if (response && response.score) {
      document.getElementById('vulnerability-score').textContent = `Vulnerability Score: ${response.score}`;
      document.getElementById('score-slider').value = response.score;
      document.getElementById('score-slider').disabled = false;
    } else {
      document.getElementById('vulnerability-score').textContent = 'Error fetching score';
    }
  });

  // Add event listener for the "Open Webpage" button
  document.getElementById('open-webpage').addEventListener('click', function () {
    chrome.tabs.create({ url: chrome.runtime.getURL('webpage.html') });
  });

  // Handle the closePopup message to close the popup
  chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
    if (request.action === 'closePopup') {
      window.close();
    }
  });

  // Function to send the URL to your API
  function sendUrlToApi(url) {
    // Replace 'YOUR_API_ENDPOINT' with your actual API endpoint
    fetch('YOUR_API_ENDPOINT', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Add any other headers you might need
      },
      body: JSON.stringify({
        url: url,
      }),
    })
      .then(response => response.json())
      .then(data => {
        // Handle the response from the API
        console.log('API Response:', data);
        // You can update the popup UI with the API response if needed
      })
      .catch(error => {
        console.error('Error sending URL to API:', error);
        // Handle the error if needed
      });
  }
});
