// popup.js
document.addEventListener('DOMContentLoaded', function () {
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, function (tabs) {
    let url = tabs[0].url;
    document.getElementById('captured-url').textContent = `Captured URL: ${url}`;

    // Send the URL to your API
    sendUrlToApi(url);
  });

  // Function to send the URL to your API
  function sendUrlToApi(url) {
    const apiUrl = `http://127.0.0.1:8000/${encodeURIComponent(url)}`;

    // Check if the constructed URL looks correct
    console.log('Constructed URL:', apiUrl);
    // Replace 'YOUR_API_ENDPOINT' with your actual API endpoint
    fetch(`http://127.0.0.1:8000/${encodeURIComponent(url)}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Add any other headers you might need
      }
    })
      .then(response => {
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        return response.json();
      })
      .then(data => {
        // Handle the response from the API
        console.log('API Response:', data);
        // Update the popup UI with the API response
        if (data && data.score) {
          document.getElementById('vulnerability-score').textContent = `Vulnerability Score: ${data.score}`;
          document.getElementById('score-slider').value = data.score;
          document.getElementById('score-slider').disabled = false;
        } else {
          document.getElementById('vulnerability-score').textContent = 'Error fetching score';
        }
      })
      .catch(error => {
        console.error('Error sending URL to API or handling response:', error);
        // Handle the error if needed
      });
  }
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

  
