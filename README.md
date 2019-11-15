# Office-365-Password-Spray

For this script to work, two things need to be installed/present. The script *should* install these dependencies for you, but if not, see below:

1) Microsoft Online Services Sign-in Assistant
2) The MSOnline module

Here's how you do that:

1. Install the 64-bit version of the Microsoft Online Services Sign-in Assistant: https://go.microsoft.com/fwlink/p/?LinkId=286152
2. Install the Microsoft Azure Active Directory Module for Windows PowerShell with these steps:
3. Open an elevated Windows PowerShell command prompt
4. Run this command: Install-Module MSOnline
5. If prompted to install the NuGet provider, type Y and press ENTER.
6. If prompted to install the module from PSGallery, type Y and press ENTER.

Script accepts two arguments (both are required): Password and UserList

Example usage: .\O365-spray.ps1 -Password Summer2018! -UserList .\userlist.txt
