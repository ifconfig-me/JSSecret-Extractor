# JSSecret-Extractor
This python based tool can be used to discover API keys, access tokens, and other sensitive data in JavaScript files. It can scan JavaScript files in a specified folder, analyze the content using various regex patterns, and output the results either in a CLI format or as an HTML report with highlighted matches.

**Note**: Since the tool is entirely based on REGEX there will be false positives, make sure to check manually for confirmation.

## Thank you

This script is forked from [@m4ll0k's SecretFinder](https://github.com/m4ll0k/SecretFinder). I modified the script to run against a list of URLs and display a neat output in the terminal or as an HTML file.

**Sample HTML output:**

![image](https://github.com/user-attachments/assets/42514394-7be1-47c5-a9e0-7f77783a6442)

**Sample CLI output:**

![image](https://github.com/user-attachments/assets/b6bbbbd9-e84b-4775-8333-ffd681470a4d)

## Features

* Scans JavaScript files for sensitive information
* Supports multiple regex patterns for various API keys and tokens
* Outputs results in both CLI and HTML formats
* Highlights different types of sensitive data with different colors

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/ifconfig-me/JSSecret-Extractor.git
    cd JSSecret-Extractor
    ```
2. **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    Alternatively, you can manually install the dependencies:
    ```bash
    pip install jsbeautifier requests lxml colorama
    ```
## Usage

1. **Basic usage:**
    To scan a folder containing JavaScript files and output the results to an HTML file:
    ```bash
    python JSSecret-Extractor.py -i /path/to/your/js/folder -o output.html
    ```
2. **CLI output:**
    To scan a folder and print the results directly to the console:
    ```bash
    python JSSecret-Extractor.py -i /path/to/your/js/folder -o cli
    ```
3. **Additional options:**
    - **`-r, --regex`**: RegEx for filtering purposes against found endpoints (e.g., `^/api/`).
    Example:
    ```bash
    python JSSecret-Extractor.py -i /path/to/your/js/folder -o output.html -r "^/api/"
    ```
## Example

**Sample HTML output:**

![image](https://github.com/user-attachments/assets/42514394-7be1-47c5-a9e0-7f77783a6442)

**Sample CLI output:**

![image](https://github.com/user-attachments/assets/b6bbbbd9-e84b-4775-8333-ffd681470a4d)

