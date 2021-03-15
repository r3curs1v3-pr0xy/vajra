&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;![logo](https://github.com/r3curs1v3-pr0xy/vajra/blob/main/images/logo.png)<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;![NPM Version](https://img.shields.io/npm/v/npm.svg?style=flat)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![contribution](https://camo.githubusercontent.com/f5054ffcd4245c10d3ec85ef059e07aacf787b560f83ad4aec2236364437d097/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f636f6e747269627574696f6e732d77656c636f6d652d627269676874677265656e2e7376673f7374796c653d666c6174)
[![PyPi Python Versions](https://img.shields.io/pypi/pyversions/yt2mp3.svg)](https://pypi.python.org/pypi/yt2mp3/)
[![OpenCollective](https://opencollective.com/vajra/backers/badge.svg)](https://opencollective.com/vajra) 
![Demo Youtube](https://camo.githubusercontent.com/80760ab9f96d5aae23525bf95b1fddf638860c80f80100a963ae61bb80ec4dc6/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f64656d6f2d796f75747562652d626c75652e737667) <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;An automated web hacking framework for web applications 
## Table of Content
- [About Vajra](#about-vajra)
    * [What is Vajra](#what-is-vajra)
    * [Key Feaures](#key-features)
    * [What Vajra does](#what-vajra-does)
- [Installation](#installation)
- [Tools Used by Vajra](#tools-used-by-vajra)
- [Contributing](#contributing)
- [License](#license)
- [Future Plans/Under Development](#Future-PlansUnder-Development)
- [Credits](#credits)
- [Disclaimer](#disclaimer)
- [FAQ](#faq)

#### Detailed insight about Vajra can be found at
https://hackwithproxy.medium.com/introducing-vajra-an-advanced-web-hacking-framework-bd8307a01aa8
<br>
## About Vajra
![logo](https://github.com/r3curs1v3-pr0xy/vajra/blob/main/images/home.png)<br>

Vajra is an automated web hacking framework to automate boring recon tasks and same scans for multiple target during web applications penetration testing. Vajra has highly customizable target scope based scan feature. Instead of running all the scan on target, it runs only those scan selected by you which will minimize unnecessary traffic and stores output in one place at CouchDB.

Vajra uses most common open source tools which every Bug Hunter runs during their testing on target. It does all the stuffs through web browser with very simple UI that makes it absolute beginner friendly framework. 

Analyzing your data from scan result is very important in Bug Bounty. The chances of missing anything is less only if you could visualize your data in proper way and Vajra does so with a lot of filters.

I created this project for my personal use (about 6 months ago)  but looking at its usefulness, I decided to make it open-source so that it can save your time and can get some more improvement from community.

#### Currently, I added only 27 unique bug bounty feature to it but more will be added in near future.
<br>

**Visit this URL for Demo:** https://hackwithproxy.tech/login

None of the scan will work in demo website.
Username: root
password: toor
# Demo
[![Demo Video](https://github.com/r3curs1v3-pr0xy/vajra/blob/main/images/demo.png)](https://www.youtube.com/watch?v=WLurj5Lg8cI)

## Key Features
 - Highly target specific scan
 - Run multiple scans in parallel
 - Highly customizable scan based on user requirements
 - Absolute beginner friendly Web UI
 - Fast (as it is Asynchronous)
 - Export result in CSV or directly copy to clipboard
 - Telegram Notification

## What Vajra does

 - [x] Subdomain Scan with IP, Status Code and Title.
 - [x] Subdomain Takeover Scan
 - [x] Port Scan 
 - [x] Endpoints Discovery
 - [x] Endpoints with Parameter Discovery
 - [x] 24/7 Monitor Subdomains
 - [x] 24/7 Monitor JavaScript
 - [x] Templates Scan using Nuclei
 - [x] Fuzz endpoints to find hidden endpoints or critical files (e.g .env)
 - [x] Extract JavaScripts
 - [x] Fuzz with Custom Generated wordlist
 - [x] Extracts Secrets (e.g api keys, hidden javascripts endpoints)
 - [x] Checks for Broken Links
 - [x] Filter Endpoints based on extensions
 - [x] Favicon Hash
 - [x] Github Dorks
 - [x] CORS Scan
 - [x] CRLF Scan
 - [x] 403 Bypasser
 - [x] Find Hidden Parameters
 - [x] Google Hacking
 - [x] Shodan Search Queries
 - [x] Extract Hidden Endpoints from JavaScript
 - [x] Create target based Custom Wordlist
 - [x] Vulnerability Scan
 - [x] CVE Scan
 - [x] CouchDB to store all scan output

#### Total Scans
![scans](https://github.com/r3curs1v3-pr0xy/vajra/blob/main/images/scan.png)
<br>
#### Result of Scan
![result](https://github.com/r3curs1v3-pr0xy/vajra/blob/main/images/scanned%20%20result.png)
<br>
#### Found Subdomains
![subdomains](https://github.com/r3curs1v3-pr0xy/vajra/blob/main/images/subdomains.png)
<br>
#### Subdomain Monitoring
![subdomain monitor](https://github.com/r3curs1v3-pr0xy/vajra/blob/main/images/monitoring.png)
<br>


## Installation
All the installation instructions are available at wiki page. Find the wiki documentation here:

https://github.com/r3curs1v3-pr0xy/vajra/wiki/Installation

## Tools used by Vajra
All the tools used by Vajra are listed here: [Link](https://github.com/r3curs1v3-pr0xy/vajra/blob/main/CREDITS.md)


## Contributing
Thank you for your consideration for making your valuable contributions to Vajra! Start by taking a look at the below mentioned points

- Fix any issues/bugs
- Solve opened issues
- Clean code
- Add any new features
- Works on [Future Plans/Under Developement](#Future-PlansUnder-Development)
- Support this project by sponsoring/donating


#### Financial Contributors icon with url will be shown here:

#### Code Contributors icon with url will be shown here:

#### If you have some new idea about this project, issue, feedback or found some valuable tool feel free to open an issue or just DM me via [@r3curs1v3_pr0xy](https://twitter.com/r3curs1v3_pr0xy)


## If you like Vajra and wants to support

[![cofee](https://camo.githubusercontent.com/c3f856bacd5b09669157ed4774f80fb9d8622dd45ce8fdf2990d3552db99bd27/68747470733a2f2f7777772e6275796d6561636f666665652e636f6d2f6173736574732f696d672f637573746f6d5f696d616765732f6f72616e67655f696d672e706e67)](https://www.buymeacoffee.com/r3curs1v3pr0xy)
#### Paypal: https://www.paypal.me/r3curs1v3pr0xy<br>
#### Bitcoin: 3EB5AsRrzSjMXnPDwSuxnyW1cc2APSHEWr
#### 10% of total donation will go to [Animal Aid Unilimited](https://www.animalaidunlimited.org/).
 

## License
It is distributed under the GNU GPL v3 license License. See [LICENSE](https://github.com/r3curs1v3-pr0xy/vajra/blob/main/LICENSE) for more information.

## Future Plans/Under Development
- Add feature to upload wordlist for bruteforcing
- Add slack/discord notification
- Improve Result UI
- Add server console through web interface
- Schedule Scan
- Take Notes in web UI

## Credits

Please take a look at [CREDITS.md](https://github.com/r3curs1v3-pr0xy/vajra/blob/main/CREDITS.md)

## Disclaimer

Most of these tools have been developed by the authors of the tool that has been listed in [CREDITS.md](https://github.com/r3curs1v3-pr0xy/vajra/blob/main/CREDITS.md). I just put all the pieces together, plus some extra magic.

This tool is for educational purposes only. You are responsible for your own actions. If you mess something up or break any laws while using this software, it's your fault, and your fault only. 

## FAQ

- #### What is the accuracy of this framework?<br>
=> Vajra uses only open source tools and scripts so its accuracy depends upon those tools.
- #### What is scalability of this framework?<br>
=> It depends upon the resources you provide to run it.
- #### Does it gives immediate result?<br>
-=> Although Vajra uses asynchronous methods but still it takes some time to complete all the scan. You can see your running scans through ongoing scan tab

 
