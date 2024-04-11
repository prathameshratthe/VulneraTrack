Chrome Extension to Display Website Security Rating
 
Feuna Khan, Mansi Mishra, Riya Kashikar, Arnav Balpande & Prathamesh Ratthe
Under the guidance of Prof. Harshala Shingne.
Shri Ramdeobaba College of Engineering and Management, Nagpur.

ABSTRACT:

Website security is paramount in today's digital landscape. Our extension rigorously assesses SSL/TLS encryption, content security, and HTTP headers, and conducts vulnerability scans. With a user-friendly interface, it delivers understandable security ratings for both technical and non-technical users. Customers can tailor preferences for personalized updates, empowering website owners to bolster security measures. Bridging the gap between user risk and website safety, this project equips users with tools and insights to navigate websites securely, fostering a safer online environment for all. 
Our extension prioritizes website security by thoroughly assessing SSL/TLS encryption, content security, and HTTP headers. It provides user-friendly interfaces that make security ratings accessible to all users. Customizable preferences enable personalized updates, allowing website owners to improve security measures. This project bridges the gap between user risk and website safety by providing tools and insights for safe website navigation and promoting a safer online environment.

Keywords - Website security, Cybersecurity assessment, Chrome extension, Vulnerability scanning


INTRODUCTION: 

When we browse the internet, we can’t always tell if a website is safe or not. This lack of clarity leads us to dangers like identity theft and malware infection on the devices. The internet provides an appropriate way for users to decide whether a website is secure or not, leaving users unsafe.

To meet this crucial demand, we offer an effective and user-friendly approach: a Chrome Extension for Website Security Rating. This extension, which is seamlessly embedded into the Google Chrome browser, behaves as a secure companion, continuously monitoring the safety of websites in real-time across users through the internet. The main purpose of this project is to provide users with appropriate information about website security, thus enhancing overall protection against countless cyber-related risks that exist in the digital world.

The Chrome Extension provides a safety score to every website that a user browses. It performs this by looking at important safety parameters like whether the website has security certifications and whether there exist any possible vulnerabilities. The extension provides a simple and easy-to-understand interface that enables users to quickly figure out how secure a website is. This immediate review is like having a helpful guide, offering data that helps you make the right decisions concerning the websites across the internet.

Our objective is to provide users with the information and resources they need to be secure while browsing the internet. In today's digital era, where risks are frequently emerging, the Chrome Extension offers a user-friendly and proactive security solution. This Chrome Extension for Website Security Rating is more than just a tool; it's a companion in the ongoing battle to make the internet a safer place for everyone.

LITERATURE SURVEY TABLE: 

In the study by Sandeep Kumar titled "Understanding Web Application Vulnerabilities," prevalent vulnerabilities such as SQL injection, XSS, and CSRF were identified (Source: 10.1109/ICRITO.2017.8342469).

Jin-Cherng Lin, in "The Automatic Defense Mechanism for Malicious Injection Attack," proposed effective defense mechanisms against malicious injection attacks, emphasizing the implementation of input validation, parameterized queries, and stored procedures (Source: 10.1109/CIT.2007.21).

Leonardo Leite, in the paper "A Survey of DevOps Concepts and Challenges," discussed the adoption of DevSecOps practices and automation for continuous security testing (Source: $10.1145 / 3359981$).

A Security Analyst, in the work "Attack and Defense Analysis of an Open Source Web Application," explored the growing significance of Content Security Policy (CSP) in mitigating XSS attacks (Source: 10.7939/r3-c80p-c936).

Nilaykumar Kiran Sangani and Haroot Zarger, in "Machine Learning in Application Security," discussed the application of machine learning and artificial intelligence for identifying and mitigating web application threats (Source: 10.5772/intechopen.68796).

Nan Sun, in the paper "Cyber Threat Intelligence Mining for Proactive Cybersecurity Defense: A Survey and New Perspectives," advocated for a proactive and dynamic security approach to adapt to evolving threats (Source: 10.1109/COMST.2023.327328tir).

The 2017 OWASP Top 10 identifies key areas of application security on the web, including injection, authentication cracks, XSS, and insufficient access. These vulnerabilities can lead to unauthorized access, deletion of data, and remote access. Solving these problems is important to ensure the security of web applications.

Cenzic's 2014 Application Vulnerability Trends report highlights security issues occurring in web applications. Identifies vulnerabilities such as SQL injection, cross-site scripting (XSS), and insecure encrypted storage. These findings highlight the continued need for effective security measures to protect against cyber threats online.

METHODOLOGY:

Objective Definition:

This project aims to develop a simple Chrome extension that performs accurate and automated security checks to improve website security.  The primary goal is to address common risks and weaknesses in web applications so that users can assess the security of websites they visit regularly. 

This extension offers a convenient and easily navigable tool for real-time security checks on visited websites, suitable for both technical and non-technical users. By applying forefront scanning techniques coupled with well-established security methodologies, the extension will be able to detect potential vulnerabilities such as outdated libraries, insufficient encryption protocols, mixed content, cross-site scripting (XSS), and insecure scripts. 

Moreover, the extension attempts to provide comprehensible results by utilizing 
an easy-to-use interface offering actionable insights reducing security threats that have been detected. The aim is to provide a workable solution that encourages user knowledge and proactive efforts in securing online experiences, in keeping with the growing significance of web security.



Fig. 2.1

Fig 2.2


In Fig 2.1 main file of execution is shown. It also depicts the parameters like HTTP status, SSL certificate, security headers, DNS, whois, and google safe browsing.
Fig 2.2 shows the method to fetch url, send to the extension, and sending url back from the extension to the popup.

Development Approach:

The development methodology for this Chrome extension relies on a seamless combination of user-friendly functionalities with automated security checks that accelerate the assessment of website security. The URL of the website that was visited will be retrieved by the extension to start its operation. After that, this URL will be sent to an API created and designed specifically for conducting comprehensive security assessments. 

After receiving the URL the API will use different parameters to run many security assessments. These parameters will include a broad spectrum of attributes essential for determining the website's overall security posture. This involves but is not limited to, evaluating the strength of SSL/TLS encryption, looking for potential security holes in HTTP headers, assessing content security policies, finding potential cross-site scripting (XSS) vulnerabilities, and close monitoring of the existence of outdated libraries or insecure scripts.
	
An easy-to-use interface for presenting security assessment results will be made possible by the seamless information transfer as a result of the API and extension integration. It will provide information on vulnerabilities found, their degrees of severity, and practical suggestions for users to effectively minimize any risks. This strategy attempts to provide users the ability to make knowledgeable decisions about the security of the websites they frequently visit by combining the power of automated security checks with an easily navigable interface.


Fig 2.3

Fig 2.4

Fig 2.5

Fig 2.3 shows the score initialized to different parameters whereas Fig 2.4 shows that the rating is scored by summing and averaging.
Fig 2.5 ‘VulneraTrack Extension’ is the name given to the extension build in this project.


III. SYSTEM DESIGN AND ARCHITECTURE: 

Functional Requirements:
	 The extension must perform a systematic procedure in which it retrieves the URL of the webpage the user has visited at the user's request. After that, an Application Programming Interface (API) created especially to evaluate website security is reached via this URL. The API is responsible for conducting a multifaceted evaluation using a variety of parameters to determine the website's overall security posture.

Technology Stack:
	To create the user interface and guarantee a responsive and interactive user experience, the frontend development toolkit of choice primarily consists of  JavaScript (JS), HTML, and CSS.  The visual components, interactivity, and overall appearance of the browser extension are all highly dependent on these technologies.
	FastAPI, a modern web framework for building RESTful APIs in Python has been selected for the backend.FastAPI is appropriate for managing API functionalities because it provides excellent performance and makes request handling more efficient. 
	
	Comprehensive security assessments are carried out using multiple parameters and tools in the backend processes. These include:
	
HTTP Response Headers: Analyzing and interpreting headers for security-related information like Content-Security-Policy, X-Frame-Options, etc., to evaluate the website's security posture.

Open Source Databases: Making use of open-source databases to store and handle information gathered about security audits and evaluation outcomes.

Web scraping: The process of extracting pertinent security-related data from websites or other resources to support security analysis.

DNS Information: Obtaining and examining DNS data to learn more about the domain name and related records of the website.

WHOIS Lookup: Performing WHOIS lookups to obtain ownership details, domain registration information, and other pertinent data for additional analysis.

SSL/TLS Analysis: Verifying and evaluating SSL/TLS certificates to make sure the right encryption and security measures are in place.

  ARCHITECTURE DIAGRAM:  


IV. RESULTS AND DISCUSSION:

In this modern world where online security is an emerging issue, this project aims to develop a Chrome extension that aims to provide users with real-time website security.
This extension is necessary because website security is transparent, which may result in some problems such as malware bugs, identity theft, and data breaches. We aim to empower individuals by providing users with a  tool that calculates the security of websites they visit.
This extension will give users features like real-time security scores, SSL certificate details, and malware detection. 

The concept of our website vulnerability detection extension does not rely on AIML (Artificial Intelligence Markup Language) or any user database. This involves creating a lightweight, rule-based extension that operates directly on the client without storing user-specific data. The rules are predefined criteria and patterns utilized by the extension to recognize and highlight potential risks or vulnerabilities within the web application.


Fig 4.1
Here's a high-level overview:

Architecture:

User-Side Extension:
  - The extension is meant to work as an extension for the browser and perform on the user's side.
  - The extension would not require any processing on the server and work with major browsers.

2. Rule-Based Detection:
   - Employing a rule-based approach to identify common vulnerabilities involves analyzing the website's source code and behavior. 
- This process includes covering known patterns of vulnerabilities, like SQL injection, XSS (Cross-Site Scripting), or insecure HTTP requests.

3. Static Code Analysis:
   - Implementing static code analysis to identify potential security flaws in the website's HTML, JavaScript, and other client-side scripts.


- It involves searching for patterns that match known vulnerabilities and raising alerts accordingly.

4. Dynamic Analysis:
   -Performing dynamic analysis involves simulating user interactions with the website.
   - Checks for vulnerabilities that may only be apparent during runtime, such as DOM-based vulnerabilities.






Fig 4.2

Fig 4.3

Fig 4.1 shows the Security Score of the website named EC-Council. As the score displayed is 7, it’s a secure website, whereas in Fig 4.2 the Security Score is just 2, therefore it shows that the fetched URL is vulnerable. Also, if we look at the Security Score in Fig 4.3 we can see that score is 5 which depicts that the website is neither fully safe nor fully vulnerable





Features:

1. Notifications and Alerts: 
- Send out notifications and alerts in real-time when possible vulnerabilities are found.
 -Make use of discreet pop-ups or alerts to notify the user of the problems discovered.

2. Configurability: 
- Give users the ability to personalize the severity levels or enable or disable particular vulnerability checks; 
- Let users configure the extension according to their needs.

Privacy and Security:

While this rule-based approach is useful for certain types of vulnerabilities, a comprehensive security strategy also includes server-side analysis and regular updates to address emerging threats.

1. No User Database:
   - Any user-specific data is avoided and not included in this extension to prioritize user privacy.

  - Operate solely based on the analyzed website and the regulations established within the extension, such as those crafted to 
identify and flag potential SQL injection vulnerabilities, cross-site scripting (XSS) patterns, insecure HTTP requests, or other recognized security flaws. 

2. Encrypted Communication (if needed):
   - If there is a need for any communication (e.g., rule updates), ensure that it is done securely over HTTPS.

3. Clear Data Handling Policies:
   - Communicate to users how data is handled, and ensure that no sensitive information is collected or transmitted.

By adopting a rule-based approach on the client side, this extension can provide a degree of vulnerability detection without the need for AIML or user databases, prioritizing user privacy and security. Remember that although this method works for some vulnerabilities, a thorough security plan should also include server-side analysis and frequent updates to handle new threats.
 These extensions play a crucial role in ensuring the security of websites and web applications by detecting and minimizing potential threats. This Research paper covers various aspects, including vulnerability detection techniques, methodologies, and tools.

Here are some general themes and findings you might encounter in this research paper related to website vulnerability analysis:
 The paper discusses different techniques for identifying vulnerabilities, such as static analysis, dynamic analysis, and interactive testing.

 Vulnerability Detection Techniques:

    - This paper emphasizes best practices for securing web applications, both from a development and deployment perspective.

   - Secure coding practices and frameworks are discussed.

   - Emerging threats and trends in web application security are explored.

Through a collaborative effort, our project seeks to create an innovative solution that not only
informs users about website security but also revolutionizes their online experience. By the end of the project, we aspire to deliver a valuable extension that reduces online
vulnerabilities and fosters a safer online environment for all users.


V. FUTURE WORKS:

Behavioral analysis and anomaly detection:
Incorporating ML or behavioral analysis techniques that might help in detecting possible vulnerabilities.



Enhanced Phishing Protection:
 Implementing advanced phishing detection mechanisms within the extension to identify and warn users about potential phishing attempts or deceptive websites.

Embedded badge next to URL in web search results: 
Users may receive immediate visual clues about a site's security status by clicking on the security emblem that appears next to URLs in online search results. By enabling users to swiftly evaluate a website's security before visiting, this feature has the potential to become standard, improving browsing safety.


VI. CONCLUSION: 

In conclusion, the research on a website vulnerability detection extension without using AIML or any user database underlines the significance of prioritizing user privacy while enhancing web security. The extension, operating solely on the client side through a rule-based approach, demonstrates its efficiency in identifying common vulnerabilities such as SQL injection, XSS, and insecure HTTP requests. Because of its lightweight design and flexible configuration, people may customize the extension to suit their preferences, making it a more user-friendly experience. While the extension provides valuable security measures for client-side vulnerabilities, it is essential to recognize its role as part of a broader security strategy.

When it comes to finding vulnerabilities on websites, building a strong security system involves paying attention to the basics. This includes thoroughly examining the website's code, configuration files, and dependencies for potential issues. Recommendations include integrating server-side analysis and regular updates to address emerging threats, emphasizing the collaborative effort required for comprehensive web security, and a feature where a badge or indicator is displayed next to a URL in web search results.

By carefully considering the fundamental parameters, a website vulnerability detection system can reinforce its capacity to proactively identify and mitigate security risks, contributing significantly to the overall flexibility of web applications. In summary, the research highlights the feasibility and advantages of a privacy-conscious approach to website vulnerability detection, offering users a proactive and adaptable tool for safeguarding their online experiences.

The research paper published PHP Aspis, part of a defect tracking system to reduce injection attacks in web applications. As presented at the 2011 2nd USENIX Web Application Development Conference, PHP Aspis can detect and prevent malicious injections by monitoring corrupted files, thus improving the security of PHP-based web applications.





VII. REFERENCES:

[1] Kumar, Sandeep & Mahajan, Renuka & Kumar, Naresh & Khatri, Sunil Kumar. (2017). A study on web application security and detecting security vulnerabilities. 451-455. 10.1109/ICRITO.2017.8342469.

[2] Marashdeh, Abdalla Wasef & Zaaba, Zarul. (2016). Cross-Site Scripting: Detection Approaches in Web Application. International Journal of Advanced Computer Science and Applications. 7. 10.14569/IJACSA.2016.071021.

[3] M. Agreindra Helmiawan, E. Firmansyah, I. Fadil, Y. Solivan, F. Mahardika and A. Guntara, "Analysis of Web Security Using Open Web Application Security Project 10," 2020 8th International Conference on Cyber and IT Service Management (CITSM), Pangkal, Indonesia, 2020, pp. 1-5, doi: 10.1109/CITSM50537.2020.9268856.

[4] Jain, Atishay & Aadithya Narayanan, M. & Anand, Aniket & Maheshwari, Harsh & Gonge, Sudhanshu & Joshi, Rahul & Kotecha, Ketan. (2023). Web Scanner: An Innovative Prototype for Checking Web Vulnerability. 10.1007/978-3-031-21435-6_58.

[5] Roy, Ritocheta, Siddharth Mandal, Saguturu Kavya, Seetha Sai Dedeepya, Alpana Singh, Elluri Lokesh Reddy, Rujula Nitin Patil and Jaya Subalakshmi Ramamoorthi. “Real-time XSS Vulnerability Detection.” 2023 3rd International Conference on Intelligent Technologies (CONIT) (2023): 1-6.

[6] Abdulsahib, G. M., & Khalaf, O. I. (2018). Comparison and evaluation of cloud processing models in cloud-based networks. International Journal of Simulation--Systems, Science & Technology, 19(5).

[7] Alazab, A., & Khresiat, A. (2016). New strategy for mitigating SQL injection attack. International Journal of Computer Applications, 154(11).

[8] Backes, M., Bugiel, S., & Derr, E. (2016). Reliable third-party library detection in Android and its security applications. Paper presented at the Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security.

[9] Cenzic. (2014). Application Vulnerability Trends Report:2014.

[10] Chen, Y., Jin, B., Yu, D., & Chen, J. (2018). Malware Variants Detection Using Behavior Destructive Features.

[11] Feng, C., & Zhang X.. A static taint detection method for stack overflow vulnerabilities in binaries. The Paper was presented at the 4th International Conference on Information Science and Control Engineering (ICISCE).

[12] Medhane, M. (2013). R-WASP: real-time-web application SQL injection detection and prevention. International Journal of Innovative Technology and Exploring Engineering (IJITEE), 2(5), 327-330.

[13] Nithya, R. R. (2013). A survey on SQL injection attacks, their detection, and prevention techniques. International Journal of Engineering and Computer Science, 2(04).

[14] OWASP, T. (2018). 10 2017. The Ten Most Critical Web Application Security Risks. Release Candidate, 2.

[15] Papagiannis, I., Migliavacca, M., & Pietzuch, P. (2011). PHP Aspis: using partial taint tracking to protect against injection attacks. Paper presented at the 2nd USENIX Conference on Web Application Development.

[16] Pektaş, A., & Acarman, T. (2017). Malware classification based on API calls and behavior analysis. IET Information Security, 12(2), 107-117.

[17] Pietraszek, T., & Berghe, C. V. (2005). Defending against injection attacks through context-sensitive string evaluation. The Paper was presented at the International Workshop on Recent Growth in Intrusion Detection.

[18] Stock, B., Pellegrino, G., Rossow, C., Johns, M., & Backes, M. (2016). Hey, you have a problem: On the feasibility of large-scale web vulnerability notification. Paper presented at the 25th {USENIX} Security Symposium ({USENIX} Security 16).

[19] Tian, Y., Zhao, Z., Zhang, H., & LI, X.-s. (2014). Second-order SQL Injection Attack Defense Model. Netinfo Security, 11.

[20] Valeur, F., Mutz, D., & Vigna, G. (2005). A learning-based approach to the detection of SQL attacks. The Paper was presented at the International Conference on Intrusions and Malware, and Vulnerability.

[21] Wassermann, G., & Su, Z. (2007). Sound and precise analysis of web applications for injection vulnerabilities. The Paper was presented at the  ACM SIGPLAN Conference on the topic of Programming Language Design and its Implementation.

[22] WU, S.-h., CHENG, S.-b., & HU, Y. (2015). Web attack detection method based on support vector machines. Computer Science, S1.



