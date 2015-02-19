About
=====
This is LinkedIn plugin for LockInfo. To know what is LockInfo visit http://www.lockinfo.net/.

This plugin shows updates from your LinkedIn network on your lockscreen. Preview http://dl.dropbox.com/u/8498648/ios/LockInfoLinkedIn/lockinfolinkedin.html

![alt screenshot](https://dl.dropboxusercontent.com/u/8498648/ios/LockInfoLinkedIn/preview.png)

![alt screenshot](https://dl.dropboxusercontent.com/u/8498648/ios/LockInfoLinkedIn/1.png)

Getting started
---------------

To build, you can either use xcode (if you have already configured it for jailbroken apps dev) or the jailbroken app development tool called "theos". 
Visit http://iphonedevwiki.net/index.php/Theos/Getting_Started to know more about it

To start with jailbroken apps development and getting required tools, visit http://brandontreb.com/beginning-jailbroken-ios-development-getting-the-tools/

Build it
--------

If you want to build this, you will have to add one file locally, `LinkedInAuthSecrets.h` and add your LinkedIn dev api key and secret there.

	static NSString* CONSUMER_KEY = @"yourKey";
	static NSString* CONSUMER_SECRET  = @"andSecret";

Try it
------

If you don't want to build it but just wanted to try it on your phone then go to cydia on your phone and add this repo (very alpha) http://dl.dropbox.com/u/8498648/ios/LockInfoLinkedIn/repo
Then install from cydia, enable it in LockInfo settings.
