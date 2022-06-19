## YARA for IDA

Unofficial YARA IDA Pro plugin, along with an unparalleled crypto/hash/compression rule set based on  
Luigi Auriemma's signsrch signatures.  
And as a general upgraded replacement for my deprecated IDA Signsrch plugin. 


### Installation

Copy `yara4ida.dll`, `yara4ida64.dll` and the `yara4ida_rules` folder to your IDA `plugins` directory.  

The default IDA hot key is "Ctrl-Y", but can be configured to another via your IDA "plugins.cfg" config file.  

Requires IDA Pro version 7.7'ish.  

### Using
Invoke the plugin via hotkey or from the IDA Edit/Plugin menu -> "Yara4Ida".  

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;![dialog screenshot](/images/dialog_screnshot.png)

##### Options

**1) Place comments:** Automatically place match comments.  
Example "#YARA" placed comments output:      
![comments example screenshot](/images/comments_screnshot.png)    

**2) Single threaded:** Force single thread scanning. Else uses a thread per CPU core parallel scanning.  
**3) Verbose messages:** Enable to show additional operational and development messages in IDA's output window.    

##### Buttons
**[LOAD ALT RULES]:** Click to load another rules file other than the default ("signsrch_le.yar" little endian signsrch based rule set).  
* For big endian, navigate to the "yara4ida_rules/signsrch" and select "signsrch_be.yar", or "signsrch_le_be.yar" if mixed endian data such as with a little endian target with network byte order data, etc.

**[CONTINUE]:** Press to start scanning.   

After the scanning has completed the rule matches are displayed in an IDA chooser window.    
Example results output list:  
![scan results screenshot](/images/results_screenshot.png)  

##### Columns
**Address:** Virtual address where the rule match is located.  
**Description:** The rule "description" field if the rule has one.  
**Tags:** The rule name tag(s) if it has them.  
**File:** The file where the rule was loaded from.    


### Motivation
Starting with a user reporting a problem with my [IDA signsrch plugin](https://sourceforge.net/projects/idasignsrch/) (now deprecated) last year, this set me off on a new path of research. Plus being interested in all things binary signatures, pattern matching, etc., I've been meaning to play with YARA for a while.  
I first just planed to fix and upgrade my old Signrch plugin but then some ongoing design considerations lead me to search for possibly other signature/rule sets and/or other search algorithms et al.  
YARA seemed fit the bill for a few reasons:
* There are several existing tools to help devlop rules/signatures, plus IDA rule generating helpers like [Hyara](https://github.com/hyuunnn/Hyara) and [mkYARA](https://blog.fox-it.com/2019/03/28/mkyara-writing-yara-rules-for-the-lazy-analyst/).  
  Many [here](https://github.com/InQuest/awesome-yara) including many links to rules and other YARA resources.
* It's stable, with years of active development behind it, plus it's an anti-virus industry standard tool.
* There exists at least one common [crypto rule set](https://github.com/Yara-Rules/rules/tree/master/crypto) used by several other related tools, and lots of anti-malware, etc., rules available for free.  
* YARA's [Aho-Corasick algorithm](https://www.geeksforgeeks.org/aho-corasick-algorithm-pattern-searching/) has phenomenal scanning performance.

### Building

Built using Visual Studio 2022 on Windows 10.  
Dependencies:
* The official IDA Pro C/C++ SDK.
* Customized build of libyara (libs included in repo): https://github.com/kweatherman/yara
* My IDA WaitBoxEx library (included in repo)
* [Qt framework](https://www.qt.io/) headers (using the IDA SDK Qt libraries) for the UI.  
&nbsp;Using Qt 5.6.3 headers here, although IDA moved to 5.15.3 as of IDA 7.7, the previous Qt version still works without issue  
 since just the headers are required. (See my blog posts [Qt 5.4 User Interfaces for IDA Pro C/C++ plug-in development](http://www.macromonkey.com/qt-5-4-user-interfaces-for-ida-pro-cc-plug-in-development/),  
 [Qt 4.8.4 on Windows for IDA Pro C/C++ plug-in development](http://www.macromonkey.com/qt-4-8-4-on-windows-for-ida-pro-cc-plug-in-development-part-1/), [the QStringLiteral issue](http://www.macromonkey.com/building-qt-ida-plugins-and-the-qstringliteral-issue/), etc).
  

Setup in the project file, it looks for an environment variable `_IDADIR` from which it expects to find a "idasdk/include" and a "idasdk/lib" folder where the IDA SDK is located.  
Not using `IDADIR` since IDA looks for it itself and can cause a conflict if you try to use more than one installed IDA version.

### Design Notes 
There's some existing IDA Python projects using [yara-python](https://github.com/VirusTotal/yara-python) like [findcrypt-yara](https://github.com/polymorf/findcrypt-yara) and [findyara-ida](https://github.com/OALabs/findyara-ida), and since the module is binary they are pretty quick. Because of this I almost stopped there since it looked like one of these solutions would fit the bill. But then I wanted to see if I could push the performance envelope further, had to dig into libyara for additional display data anyhow, and needed to add a custom module, I went the full binary C/C++ route.
With C/C++ a single thread only yields a small performance gain. But, since I added parallel scanning (using the Windows thread pool API), got speed gains of around a 30%  while using **complex rules**. Currently, since the default Yara4Ida signrch based rule set is all binary signatures types, this parallelism only squeezes about an extra 10% since YARA's efficient Aho-Corasick algorithm pretty much saturates system memory bandwidth with just a single thread already. For more complex rules (with multiple rule parts, using regex, etc.), the extra core compute comes into play.

In switching to YARA I first planed on using existing open source rules like the crypto one mentioned above and some of the others from [Yara-Rules](https://github.com/Yara-Rules).  
At first, looked like the crypto rule set had good coverage and fitness, but on further examination I found it gave too many false positives, not nearly as many matches as the signsrch signatures, and a lot of the rules are complex (probably unnecessarily), using regex, etc., which makes the libyara scanning exponentially slower.    
I ended up circling back to the awesome signsrch again, making a tool to convert the signatures over to YARA rules. While doing this, I filtered out many signatures including most of the audio, video codec, and game specific ones lowering the total signature count down to about a thousand.

To handle the signsrch "AND" signature type, I created a custom YARA module named "area" since the needed scan behavior couldn't be constructed from YARA rules alone. For this type of search it's a match if a series of either 32bit or 64bit values are all within the same memory range (algorithmic, but within around plus or minus 3000 bytes); perfect for matching certain types of signature patterns.

Performance wise, I found simple binary type signatures to be the best. The Yara4Ida binary signature set (using 8x 5Ghz cores) scans the default ~1000 rules in a large IDA DB in about 1.6 seconds, while it takes 22.5 seconds to scan just the 116 complex "Yara-Rules" crypto ones (14x faster even at an almost 9:1 count ratio!).  
See [YARA Performance Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines/) for some YARA rule performance tips.

Finally, I removed the default "pe", "elf" and most of the other of the other default libyara modules since as it is. they are unusable from an IDA DB space. Maybe with some work and modification of the modules, it would be possible to make the current loaded IDA DB emulate at lease some of the executable format header types.

### Credits

Luigi Auriemma for his unparalleled DB of signatures from his [signsrch](http://aluigi.altervista.org/mytoolz.htm#signsrch) tool.  
Victor M. Alvarez and contributors, for the world-class [YARA: The pattern matching swiss knife](https://github.com/VirusTotal/yara).  
[Hex-Rays](https://hex-rays.com/) for IDA Pro, the state-of-the-art binary code analysis tool.  


### Licenses

Plugin code released under MIT ©2022 By Kevin Weatherman.  
Signsrch signature set: ©2013 By Luigi Auriemma, under GPL 2.0 license.  
Libyara: ©2007-2016, The YARA Authors, under BSD 3-Clause license.  
(See "LICENSE.txt" for more details)