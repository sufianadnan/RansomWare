# SPR708 Ransomware

![Banner](images/banner2.jpg)  
*Replace the above line with the actual path to your banner image.*

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Script Overview](#script-overview)
6. [Detailed Function Descriptions](#detailed-function-descriptions)
7. [Screenshots](#screenshots)
8. [Troubleshooting](#troubleshooting)
9. [Disclaimer](#disclaimer)
10. [Contributing](#contributing)
11. [License](#license)

---

## Introduction

The **Sufian Ransomware** is a simulated ransomware tool developed for educational purposes. It is designed to encrypt files on the victim's machine, display a ransom note, and provide a decryption mechanism upon receiving a valid Bitcoin transaction number. 

> **Note:** This tool is intended strictly for educational use. Please do not deploy it on any system you do not have explicit permission to test.

## Features

- **File Encryption**: Encrypts specific files on the user's desktop.
- **Custom Ransom Note**: Displays a customized ransom note using a graphical user interface (GUI).
- **Timer Countdown**: Includes a countdown timer showing the remaining time to pay the ransom.
- **Background Change**: Changes the desktop background to a predefined image.
- **Decryption Process**: Files can be decrypted upon verification of the payment.
- **Network Discovery**: Automatically discovers the backend server via UDP broadcast.

## Installation

### Prerequisites

- Python 3.x
- Required Python packages (can be installed via `requirements.txt`):
  - `customtkinter`
  - `PIL` (Pillow)
  - `requests`
  - `pycryptodome`
  - `psutil`
  - `windows-tools`

### Step-by-Step Installation

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/yourusername/SPR708-Ransomware.git
    cd Ransomware
    ```

2. **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Prepare Your Images**:
   - Place your banner image in the `images` directory.
   - Ensure you have an appropriate background image and icon for the application.
   - Update the script paths accordingly.

4. **Running the Script**:
   Simply execute the `main.py` script:
   ```bash
   python main.py
