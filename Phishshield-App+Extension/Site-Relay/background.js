chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url.startsWith("http")) {
    console.log("Sending URL:", tab.url);

    fetch("http://127.0.0.1:5000/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    })
      .then(res => res.json())
      .then(data => {
        console.log("Phishing check:", data);
        if (data.phishing) {
          chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: () => alert("⚠️ Warning: This site may be phishing!")
          });
        }
      })
      .catch(err => console.error("Error contacting agent:", err));
  }
});
