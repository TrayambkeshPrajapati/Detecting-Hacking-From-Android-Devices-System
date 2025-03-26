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
