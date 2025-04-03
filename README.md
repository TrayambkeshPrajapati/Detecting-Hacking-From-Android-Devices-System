Mobile Hacking Detection App

Overview

The Mobile Hacking Detection App is an advanced Android application designed to detect potential hacking threats on mobile devices. It scans installed applications for suspicious permissions, malware, and vulnerabilities using the VirusTotal API and provides a detailed security analysis. Additionally, it offers a temporary file cleanup feature to optimize device performance and security.

Features

User-Installed App Analysis: Scans only user-installed apps, excluding system apps.

Permission-Based Threat Detection: Detects and highlights apps with potentially dangerous permissions.

VirusTotal API Integration: Verifies app security status against the VirusTotal database.

App Icon & Name Display: Displays each app with its icon and name for easy identification.

Temporary Files Cleanup: Scans and deletes unnecessary files to free up space and enhance performance.

Threat Scan History & PDF Reports: Stores scan history and allows users to export reports as PDFs.

Lottie Animations: Provides an enhanced UI/UX experience using smooth animations.


Technologies Used
Programming Language: Java
Framework: Android Studio
API: VirusTotal API
UI/UX: Lottie Animations
Database: Local storage for scan history


Dependencies
Make sure to include the following dependencies in your build.gradle
(Module: app):

// VirusTotal API
implementation 'com.squareup.retrofit2:retrofit:2.9.0'
implementation 'com.squareup.retrofit2:converter-gson:2.9.0'

// JSON Parsing
implementation 'com.google.code.gson:gson:2.8.8'

// RecyclerView for displaying apps
implementation 'androidx.recyclerview:recyclerview:1.2.1'

// Lottie Animations
implementation 'com.airbnb.android:lottie:5.0.3'

// Permissions Handling
implementation 'com.karumi:dexter:6.2.3'

//clone the repo
git clone - repo usrl

Usage

Perform a Scan
Open the app and click Scan to analyze installed applications.
Results will show a list of potential threats and permissions used.
View Threat Details
Click on any app in the scan results to view its permissions and VirusTotal report.
Clean Temporary Files
Navigate to the Cleanup section and remove unnecessary files to free up space.

Contribution Guidelines
We welcome contributions! To contribute:
Fork the Repository
Create a Branch (git checkout -b feature-new-feature)
Commit Changes (git commit -m 'Added new feature')
Push to Branch (git push origin feature-new-feature)
Submit a Pull Request

Outputs :-

![WhatsApp Image 2025-04-03 at 14 04 35](https://github.com/user-attachments/assets/eaaad5de-23d1-426a-bc1a-1cdd6c081295)

![WhatsApp Image 2025-04-03 at 14 04 34 (1)](https://github.com/user-attachments/assets/7c552571-97e3-418f-a873-f55258b30492)

![WhatsApp Image 2025-04-03 at 14 04 34](https://github.com/user-attachments/assets/cb57ff96-93aa-463f-9c8e-ce569c808c19)

![WhatsApp Image 2025-04-03 at 14 04 33 (2)](https://github.com/user-attachments/assets/0c8e5d1e-d2bf-4192-90b7-0b9ffb3728b5)

![WhatsApp Image 2025-04-03 at 14 04 33 (1)](https://github.com/user-attachments/assets/560939a0-bf80-427e-a977-ff8b17252d45)

![WhatsApp Image 2025-04-03 at 14 04 33](https://github.com/user-attachments/assets/05040b0e-b6af-41b2-bfa6-3c908cc73a4d)
