GO_EASY_ON_ME=1
AUXILIARY_LDFLAGS += -lsubstrate

include theos/makefiles/common.mk
BUNDLE_NAME = LinkedInPlugin
LinkedInPlugin_FRAMEWORKS = Foundation QuartzCore IOKit CoreFoundation CoreGraphics GraphicsServices UIKit Security MIME Preferences
LinkedInPlugin_FILES = JSON/JSONKit.m KeychainUtils.mm Crypto/Base64Transcoder.c Crypto/hmac.c Crypto/sha1.c OAuth/OAAttachment.m OAuth/OACall.m OAuth/OAConsumer.m OAuth/OADataFetcher.m OAuth/OAHMAC_SHA1SignatureProvider.m OAuth/OAMutableURLRequest.m OAuth/OAPlaintextSignatureProvider.m OAuth/OAProblem.m OAuth/OARequestParameter.m OAuth/OAServiceTicket.m OAuth/OAToken.m OAuth/OATokenManager.m Categories/NSMutableURLRequest+Parameters.m Categories/NSString+URLEncoding.m Categories/NSURL+Base.m OAuth/OAPlaintextSignatureProvider.m LinkedInPlugin.mm


include $(THEOS_MAKE_PATH)/bundle.mk

Name=LinkedInPlugin
Bundle=com.rpatil.lockinfo.$(Name).bundle
PackageName=$(Name)_$(shell grep ^Version: control | cut -d ' ' -f 2)
ToDest=/Library/LockInfo/Plugins/
RepoPath=~/Dropbox/Public/$(Name)/repo

package:: $(Name)
	mkdir -p $(PackageName)/DEBIAN
	mkdir -p $(PackageName)/Library/LockInfo/Plugins/$(Bundle)
	cp -r Bundle/* $(PackageName)/Library/LockInfo/Plugins/$(Bundle)
	cp obj/$(Name) $(PackageName)/Library/LockInfo/Plugins/$(Bundle)
	rm *.deb
	rm -rf _
	rm -rf obj

deploy:: $(Name)
	theos/extras/anyexp.exp $(mypwd) ssh root@$(IPHONE_IP) killall SpringBoard	
	theos/extras/anyexp.exp $(mypwd) scp -r $(PackageName)/Library/LockInfo/Plugins/$(Bundle)  root@$(IPHONE_IP):$(ToDest)

release:: $(Name)
	cp control $(PackageName)/DEBIAN
	find $(PackageName) -name .svn -print0 | xargs -0 rm -rf
	dpkg-deb -b $(PackageName) $(PackageName).deb
	mkdir -p $(RepoPath)/deb_files/
	mkdir -p $(RepoPath)/uploads/
	cp *.deb $(RepoPath)/deb_files/
	rm -rf $(RepoPath)/uploads/$(PackageName)
	cp -rf $(PackageName) $(RepoPath)/uploads/
	rm -rf package
	mv $(PackageName) package
	dpkg-scanpackages -m $(RepoPath)/ /dev/null | sed 's/Filename\:.*/Filename\:.\/deb_files\/$(PackageName).deb/' > $(RepoPath)/Packages 
	bzip2 -z $(RepoPath)/Packages -c > $(RepoPath)/Packages.bz2 
