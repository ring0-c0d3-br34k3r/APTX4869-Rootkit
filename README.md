# APTX4869-Rootkit
APTX4869 Rootkit is a Kernel Mode Rootkit


![APTXxxxx](https://github.com/0xp17j8/APTX4869-Rootkit-/assets/111459558/d72eddf8-f4d2-4a21-845b-e1272ed1b3f5)



The code focuses on a specific process (OrcaMal.exe). It aims to hide or manipulate information related to this particular process when queried by system functions

"hiding the presence of a malware process from system monitoring tools. It demonstrates techniques for manipulating system calls in kernel mode"
this Rootkit operates at the kernel level of the Windows operating system. It intercepts calls to the ZwQuerySystemInformation function, which is commonly used in system-level operations to gather information about running processes - in another Words : The Rootkit is designed to hide or modify information related to a specified process (OrcaMal.exe) from being returned by the ZwQuerySystemInformation function  


This report presents an analysis of the "APTX4869 Rootkit" malware, a sophisticated C++ rootkit designed for Windows environments. The rootkit employs advanced techniques to evade detection, manipulate system processes, and establish persistent control over the infected system.


- Technical Overview :
  Language        : C++
  Target Platform : Windows


- Main Components :
  Function Hooks         : Overrides system functions such as ZwQuerySystemInformation to control information retrieval and hide 
  malicious processes.
  Memory Manipulation    : Utilizes WriteProcessMemory and ReadProcessMemory for stealth and persistence.
  Rootkit Entry          : Initializes the rootkit by hooking system functions and establishing malicious behaviors.
  Malicious Capabilities :
  Process Hiding         : Conceals specific processes from system queries, making them invisible to monitoring tools and security 
  software.
  Persistence            : Maintains control over system functions even after system reboots, ensuring long-term presence and 
  activity.
  Remote Access          : Provides a backdoor for remote attackers to control the infected system, execute commands, and exfiltrate 
  data.
  Evasion Techniques     : Utilizes advanced memory manipulation techniques to evade detection by antivirus software and other 
  security mechanisms.
 

- Detailed Analysis :
  Function Hooks         : Overrides ZwQuerySystemInformation to manipulate system information retrieval, selectively hiding 
  processes based on predefined criteria.
  Memory Manipulation    : Utilizes WriteProcessMemory and ReadProcessMemory to modify memory contents, facilitating stealth and 
  persistence.
  Process Concealment    : Specifically targets processes associated with security tools, administrative tasks, or user activity, 
  aiming to avoid detection and interference.
  Driver Initialization  : Hooks system functions during driver initialization, ensuring early control and integration into the 
  system's core functionality.


- Impact :
  Security Threat          : Poses a significant threat to system security and integrity by allowing unauthorized access and control 
  over infected systems.
  Data Breach              : Enables attackers to access and exfiltrate sensitive data, compromising the confidentiality and privacy 
  of users and organizations.



- How to use :
  you would need to compile it into a kernel-mode driver file (.sys), load it into the system using a tool like sc or fltmc, and 
  then trigger the functionality that involves querying system information
