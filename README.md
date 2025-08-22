
##  Project Title:-
PhishShield : Real-time Phishing URL Detector. 
We have developed a browser extension / App that can detect and block phishing websites in real-time, with a scoring system and visual alert for the user.

--------

## Team Details:- 

Team name = Team INIT

Team members :-
1. Milan kumar Modak
2. Abhishek Sinha
3. Abhishek Singh
4. Paras Vishwakarma

-------------
##  Problem Statement:-
PhishShield is a Chrome extension that analyzes SSL/TLS certificates of the websites you visit.  
It helps detect potential phishing attempts by checking the certificate chain, validity, and related security information.

-------

##  Project Description
   Phishing has become one of the most widespread and damaging cyber threats, targeting millions of users each year. By creating fake but convincing websites, attackers trick individuals into revealing sensitive data such as
   1. Login credentials
   2. Banking information
   3. Personal details
   
   >  These sites often impersonate trusted services—banks, e-commerce portals, social media platforms—using lookalike domains, copied designs, and even valid security certificates. 
   
   The sophistication of such attacks makes them extremely difficult for ordinary users to detect. 

-------
## 🚀 Features

### 1. Implementation(App + Relay Extension)
- Instant Notification of phishing as soon as it is detected in the browser.
- Uses a lighweight relay extension in the browser to detect url and perform API call to VirusTotal for scanning.
- Displays full verdict.
- Quick Popup Notification to ensure no harm is done to user data

### 2. Implementation(App)
- Near Instant notification of phishing as soon as it is detected in the browser.
- Scans any and all the outgoing traffic of the device to ensure no phishing attempts, and reports them as soon as possible . 
- Uses WindowsToast Notification to inform the user of phishing attempts.
- Only reports the attempts of phishing so there is no need for user to concern themselves with safe cases being notified every time.

-------

## 📂 Project Structure

PhishShield/
├── Phisheild-App/
├── Phishshield-App+Extension/
├── Phishshield-extension/
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt


-------
## Tech Stack:-
Flask
React js



---

## 🔧 Installation

1. Download and extract the repository.

#### I. PhishShield-App
1. Open the repo or use&nbsp;&nbsp;&nbsp;&nbsp; `cd Team_INIT-PhisShield`

2. Run the following command in terminal to install the required libraries. <br>
`pip install -u requirements.txt`.

3. Also download and install <a href="https://npcap.com/#download">npcap for your device.</a>

4. Run the following command in terminal.

`python PhishShield-App/start.bat`

#### II. PhishShield-App+Relay Extension
1. Open the repo or use&nbsp;&nbsp;&nbsp;&nbsp; `cd Team_INIT-PhisShield`

2. Run the following command in terminal to install the required libraries. <br>
`pip install -u requirements.txt`.

3. Also download and install <a href="https://npcap.com/#download">npcap for your device.</a>

4. Open your browser and go to  `chrome://extensions`

5. Enable `Developer Mode`.

6. Load the extension folder.

7. Now go back to the opened repo and run the following command in terminal.

8. Run the following command in terminal.

   `python PhishShield-App/start.bat`

#### III. PhishShield-App+Relay Extension
1. Open your browser and go to `chrome://extensions`
3. Enable **Developer mode**
4. Click **Load unpacked** and select the `phishshield-extension/` folder.
5. The **PhishShield** icon will appear in the extensions toolbar.

---

## 📖 Usage

1. Navigate to any **HTTPS** website.
2. Click on the **PhishShield** icon in the Chrome toolbar.
3. The popup will display:
   - Security status of the page
   - Any issues found in the certificate
   - Full PEM certificate chain

---

## 🛠 Permissions Required
- `tabs` → To get the current active tab URL
- `activeTab` → To allow analysis of the current page
- `storage` → To store certificate analysis results
- `debugger` → To access certificate details via Chrome Debugger Protocol
- `host_permissions` → To allow access to all websites

--------

## 📝 Roadmap
- Parse and display **Issuer, Subject, Validity dates, and SANs** instead of raw PEM only
- Add **phishing heuristics** (e.g., mismatched CN/SAN vs hostname)
- Support **exporting analysis reports**

----------
## Feature Enhancement
-Cloud-based Threat Intelligence Hub.
-Deploy a central server that continuously aggregates phishing reports from all users.
-Real-time updates of blacklists and heuristics for all extension users.
-Advanced Machine Learning / Deep Learning.
-Implement federated learning so models improve collaboratively without exposing user data.


