# InsecurebaknV2

 Java decompile: jadx-gui
Native decompile: IDA Pro
Hook: Frida  

[GitHub - dineshshetty/Android-InsecureBankv2: Vulnerable Android application for developers and security enthusiasts to learn about Android insecurities](https://github.com/dineshshetty/Android-InsecureBankv2)

## Static Analysis

1. decompile APK find the first Activity in AndroidManifest.xml
   
   ![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-03-34-image.png)
   
   The logic below hides the button
   
   ![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-04-33-image.png)
   
   ```
   Java.perform(function () {
       var buttonView = Java.use("android.view.View");
       buttonView.setVisibility.implementation = function (visibility) {
           console.log("param value:", visibility);
           if (visibility === 8) {
               console.log("buttonView setVisibility(GONE), changing to VISIBLE");
               visibility = 0;
           }
           return this.setVisibility(visibility);
       };
   });
   ```
   
   Frida hooked to make it visible, we got the message it's a feature in progress.

# Login Part

###### HttpRequest

login with the test account   'dinesh/Dinesh@123$' , and capture http request by Charles

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-34-07-image.png)

It's a post request and the body is username and password.

**DataStore localized**

after the request successful and finished,the username and password are saved into the sharedpreference file /data/data/com.android.insecurebankv2/shared_prefs/mySharedPreferences.xml

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-36-17-image.png)

**AES Encrypt**

And AES key is plain text hard-coded into code.

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-38-26-image.png)

also, I found there is a admin account exists in the code

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-34-59-image.png)

# Transfer  part

 **Get Account** button logic

read user account info from sharedPreferences file, and decrypt to plain uesrname/password,  the network library is HttpClient

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-43-43-image.png)

then make request to get the accounts infomation.![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-45-53-image.png)

| Post Field | value       | source                |
| ---------- | ----------- | --------------------- |
| username   | dinesh      | SharedPreference file |
| password   | Dinesh@123$ | SharedPreference file |

**Do Transfer** button logic

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-49-31-image.png)

when the request finish and success, will save the data into sdcard file

/sdcard/Statements_dinesh.html

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-54-09-image.png)

and html file content is belowing

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-54-31-image.png)

## View statement part

read html file saved last step, and show it by webview

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-56-16-image.png)

# 

# ChangePassword

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-15-59-12-image.png)

Post request with urlencode data.

After change password successful, will send broadcast to notify user

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-16-06-40-image.png)

**LogCat**

view log for App, it show the sensitive infomormation

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-16-21-45-image.png)

# Root device check

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-16-24-05-image.png)also check root device, but I didn't install these root app so it detect and show 'not root device'

# Improvements

##### Encrypt

- aes key and main logic migrate to so file

- complex encrypt  eg: RSA + AES 

- use Chromium-Cronet as network library

- Https + Mutual TLS Authentication

- Java code obfusication 

- store data should be encrypt and in the internal dir of app, 
  
  for example sdcard/infomation.html if the content changed to open the risk website by other app

- should use logutil to distinguish log levels

- an unnecessary activity should not be export=true 
   (adb shell am start -n com.example.app/.MyActivity), speically **ChangePassword**
