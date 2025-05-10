# APK-Shell

Java decompile: jadx-gui
Native decompile: IDA Pro, Ghidra,010Editor
Hook: Frida  

Android Emulator os_version=12

[owasp-mastg/Crackmes/Android at master · OWASP/owasp-mastg · GitHub](https://github.com/OWASP/owasp-mastg/tree/master/Crackmes/Android)

# Java Layer

##### 1 Run the app and encourted the crash, found the crash reason is ''Caused by: java.lang.ArithmeticException: divide by zero'

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-07-22-34-06-image.png)

##### 2 Decompile the APK file, find the reason of the crash code

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-11-54-57-image.png)

Risk environments detected logic.

###### 2.1 rb.j()   root/ROM/xposed

- Root apps packagename based on whitelist

- Device can be debug

- Command 'mount' has output contain /system/.... dir, that mean device is rooted

- Is devices ROM an offical 

- Run command  'which su' check is there some output info

- System.getenv("PATH") get environment and contact 'su', passes to another so(libtool-checker.so) function to check root device
  
  xposed installer

###### 2 rb.a()

   is check so file named libtool-checker.so loaded

###### 3 rb.e()

   passes the file name to libtool-checker.so to check root environment

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-18-30-41-image.png)

# Java Layer Bypass

There are 3 options: change smali repackage apk , hide feature, and frida hook

```
Java.perform(function () {
    var detectClass = Java.use("b.a.a.b");
    detectClass.j.overload().implementation = function () {
        var result = this.j();
        console.log(" root, risk app, ROM, JNI check, result=" + result);
        return false;
    };

    detectClass.a.overload().implementation = function () {
        var result = this.a();
        console.log("is libtool-checker.so loaded, result=" + result);
        return false;
    };

    detectClass.e.overload().implementation = function () {
        var result = this.e();
        console.log("libtool-checker.so check root device, result=" + result);
        return false;
    };
});
```

Launch the app again, it will crash in libnative-lib.so file, so we by pass the java layer, and need to continue reverse native

## Native Layer

Check init_array section of the so file, because the init_array functions called by linker, these are the functions called earlier.

   ![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-12-04-30-image.png)

###### Decompile the function and find the information

- datadiv_decode4432700155380705947 is a function used for decrypt data

- sub_83DC and sub_4A4DC, functions too big to be decompiled, need to change IDA config function size in hexrays.cfg and use Ghidra to view the code.

- SO file uses the ollvm obfuscation
  
  Many functions in init_array, it is necessary to analyze so file in combination with linker, use the following command to pull linker which from my device

```
adb pull /apex/com.android.runtime/bin/linker64
```

Based on android source code

https://cs.android.com/android/platform/superproject/+/android-mainline-12.0.0_r121:bionic/linker/linker_soinfo.cpp;l=488

   ![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-12-19-05-image.png)

 Usually need to set a breakpoint in linker address in memory to enter init_array function. 

In addition, we can **hook linker at address 0xB5E04 then sleep the application 15s**, and we attach the process within 15s.

```
 Interceptor.attach(linker64_module.add(0xB5E04), {
        onEnter: function (args) {
            var str = args[3].readCString();
            console.log("linker==>" + str);
            if (args[3].readCString().match("libnative-lib.so")) {
                var usleep = new NativeFunction(Module.findExportByName(null, 'usleep'), 'int', ['uint']);
                usleep(15000000);
                console.log("application resumes");
            }
        }, onLeave: function (result) {

        }
    });
```

   In function data div_decode4432700155380705947, It can be seen that decyprt data between **byte_163108** and **byte_16340A**, so set breakpoint at end of the function to dump decrypted data.

```
import idc
import ida_bytes
start = 0x163108   
end = 0x16340A    
data = ida_bytes.get_bytes(start, end - start)
with open("/tmp/init_array_data.bin", "wb") as f:
    f.write(data)
print(f"Dumped {end - start} bytes from {hex(start)} to {hex(end)}")
```

   ![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-13-34-45-image.png)

   Most likely these data will be used to detect risk features, frida/root/debugging

   ![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-13-38-30-image.png)

   To patch the SO file, need to find the data address in the original binary, can search in 010editor,and get the address 0x153108

search encrypted data address 0x6F, 0x6A, 0x61, 0x60

   ![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-13-41-10-image.png)

   use python script to patch the decrypted data

```
import shutil
dec_str_bin = '/tmp/init_array_data.bin'
original_so = dir + 'libnative-lib.so'
decstr_so = dir + 'libnative-lib.decstr.so'
f = open(dec_str_bin, 'rb')
decrypted_data = f.read()

origin_addr = 0x153108

shutil.copyfile(original_so, decstr_so)

f_dec_so = open(decstr_so, 'r+b')
f_dec_so.seek(origin_addr)
f_dec_so.write(decrypted_data)
```

In fact, the decrypted part of the data is a string, encrypted by Armariris.

Armariris it's principle is that init_array it will decrypt strings

After decrypting the string, can find some key detection information.

###### Continue to find the crash reason

   ![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-12-21-20-image.png)

 #00 pc 0000000000038f7c exists in function sub_20954

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-12-22-13-image.png)

****

decompile sub_20954, found frida detect and IDA detect logic

by the way, after patch the string decryptbin, it's easy to find the hook/debug feature

Frida feature: gmain 

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-19-05-36-image.png)

IDA feature: TracePid

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-19-03-51-image.png)

sub_83DC -> pthread_create(sub__20954) -> detect IDA, frida

sub_4A4DC -> pthread_create(sub__20954) -> detect root

then nop these detect function

```
  var libfoo_module = Module.findBaseAddress('libnative-lib.so');
  Interceptor.replace(libfoo_module.add(0x20954), 
                  new NativeCallback(function () {
                    console.log("linker==>   0x7a660 nop");
                    return;
                }, 'void', []));
                Interceptor.replace(libfoo_module.add(0x7a660), 
                  new NativeCallback(function () {
                    console.log("linker==>   0x7a660 nop");
                    return 0n;
                }, 'int64', []));
```

so far we have bypassed Java Detect and native detect, and app don't crash now.

<img title="" src="file:///Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-14-37-12-image.png" alt="" width="378">

When clicking the GENERATE R2COIN button, the app still crash

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-14-38-16-image.png)

continue to check button click event, it call native method 

```
public native byte[] gXftm3iswpkVgBNDUp(byte[] bArr, byte b2);
```

```
// Jni Table
struct JNINativeInterface {
    ... ...   
    jclass (*FindClass)(JNIEnv*, const char*);  // offset=48
    ... ... 
    jint (*RegisterNatives)(JNIEnv* env,        // offset=1720
                        jclass clazz,
                        const JNINativeMethod* methods,
                        jint nMethods);
```

so we can find the third params is real JNI Method address 0x7d124, in this function ,it call opendir function in libc.so /proc/self/task

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-14-46-34-image.png)

also **frida** feature

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-14-47-35-image.png)

and read file content in /proc/self/task/pid/status, it may **be check root or IDA debug**

![](/Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-14-48-05-image.png)

can see in the code that read /proc/self/task first, and then read /proc/self/task/%s/status one by one, and it will take more times.

We know that if **the opendir(/proc/self/task) function returns an error**, then the /proc/self/task/%s/status will not be read in the future.

In this way, we don't have to bypass each /proc/self/task/%s/stats file separately.

```
  Interceptor.attach(opendir_ptr, {
            onEnter(args) {
                this.path = args[0].readUtf8String();
                if (this.path.includes('/proc/self/task')) {
                    const newPath = "/proc/seef/task"; // change to a not exists file 
                    const pathBuf = Memory.allocUtf8String(newPath);
                    args[0] = pathBuf;
                }
            },
            onLeave(retval) {
                if (!retval.isNull()) {
                    console.log("[opendir]3 path =", this.path, 'retval=', retval);
                }
            }
        });
```

it works now and no crash happend.

<img title="" src="file:///Users/kaibing/Library/Application%20Support/marktext/images/2025-05-10-14-54-19-image.png" alt="" width="390">

# 

# Improvement

###### 1 enhance ollvm Pass for encrypting string

I have investigated previsouly, the encrypt and decrypt data exists in the stack, if the function executed finished,  and memory will be used by other function.

1. insert encrypt data at the front of function

2. insert decrypt logic below the encrypt data

###### 2 Arm directive virtualization protects so files

###### 3 Use custom  strings function

   the string function strcmp in libc.so is easy to find and hook, can custom string function in so file, for example strstr, strcmp

###### 4 Custom linker load so

| type         | saftey | compatible |
| ------------ | ------ | ---------- |
| Ollvm        | mid    | high       |
| Arm VMP      | high   | low        |
| Customlinker | high   | mid        |
