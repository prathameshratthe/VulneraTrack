// background.js
chrome.webNavigation.onCompleted.addListener(function (details) {
 chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
   const activeTab = tabs[0];
   if (activeTab && activeTab.id === details.tabId) {
     // Trigger the popup by clicking on the extension icon
     chrome.browserAction.click({ tabId: details.tabId });
   }
 });
});

chrome.runtime.onConnect.addListener(function (port) {
  port.onMessage.addListener(function (msg) {
    console.log(msg);
  });
});

chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
 if (request.action === 'sendUrl') {
   const url = request.url;
   console.log('URL received:', url);

   // Add your logic to fetch the vulnerability score from the API
   // For demonstration purposes, a random score is generated
   const randomScore = Math.floor(Math.random() * 10) + 1;

   // Send the score and URL back to the popup
   chrome.runtime.sendMessage({ action: 'sendVulnerabilityInfo', score: randomScore, url: url });
 } else if (request.action === 'closePopup') {
   chrome.tabs.sendMessage(sender.tab.id, { action: 'closePopup' });
 }
});
