// content.js
chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
 if (request.checkContentScript) {
   sendResponse({ success: true });
 } else if (request.action === 'sendUrl') {
   const url = request.url;
   console.log('Sending URL to background:', url);
   // ... rest of your code
 }
});
