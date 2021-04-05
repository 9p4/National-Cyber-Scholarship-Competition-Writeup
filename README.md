# National Cyber Scholarship Competition Writeup

## Binary

### BE01

Downloading the PDF and running binwalk on it gives us a zip file embedded in the PDF. Extracting the zip from the PDF with `binwalk --dd='.*' chicken.pdf` gives us another ZIP file. Extracting the nested ZIP files finally gives us another PDF with the flag: `wh1ch_came_f1rst?`.

### BE02

This one is a simple overflow stack smash. Spamming `a` roughly a hundred times in the input of the program gives us the flag of `luckyNumber13`.

### BM01

## Crypto

### CM01

This one appears harder than it actually is. In order to solve this one, you have to first realize that one of the images (code.png) is actually two QR codes on top of each other, with a xorred pattern. The first QR code is from frame.png, and we just have to subtract the two. In order to do this, I used GIMP and made each image a layer (with code.png on top). Then, I modified the code.png layer to use the "exclusion" mode, and got a new QR code. [See the save file](CM01.xcf). The data in this one is our flag: `A_Code_For_A_Code`.

### CM02

This is a trivial substitution cipher. Replacing all of the emojis with letters, we can run a frequency analysis on it. My substitution order looks like this: `GDCLEPJFBIHMQNOSRTKAUVYWZX, ETAONIHSRDLUMCWFYGPBVKXJQZ`. I used [Boxentriq](https://www.boxentriq.com/code-breaking/frequency-analysis) to do the frequency analysis, and [Dcode](https://www.dcode.fr/monoalphabetic-substitution) to do the solving. After running this, we find that X and Q were mixed up, and fixing that gives us the flag of `FREQUENTLY_SUBSTITUTE_FROWNY_FACE_FOR_SMILEY_FACE`.

## Forensics

### FE01

We are given a Microsoft Outlook mailbox. Let's see if we can can open it. I am installing [libpff](https://github.com/libyal/libpff) to open the mailbox. After extracting the mailbox, we see in message 18, we have an encrypted ZIP file, and the message states that the password is the same as earlier. Let's see if we can find the password. After some trawling around, we find a calendar appointment (00001) and the title has some strange characters in it: `c]5p@S7K/z}Z!Q`. Trying this as the ZIP password gives us the flag in an image of `pst_i'm_in_here!`.

### FE02

We are given a domain name. Looking at the TXT record for the domain yields us the flag of `unlimited_free_texts`.

### FE03

Extracting the image and all of the tars into one location gives us a mini-filesystem. Then, we can find the flag at `./home/secret/flag.txt`, which gives us the flag of `8191-SiMpLeFilESysTemForens1Cs`.

### FE04

Looking at the file, we can run a basic grep on it. We know it's sixteen characters, so if we run `egrep '..x............S' 50k-users.txt | grep Z` and look for the one that has a number from 2-6 after the x, we get our flag of `YXx52hsi3ZQ5b9rS`.

### FM02

Opening the file we are given in Wireshark and filtering all of the packets by IRC, we can extract an encrypted file, and get the password. Once we extract the file, we have an NES ROM image which has the flag embedded in it: `NESted_in_a_PCAP`.

## Networking

### NE01

Running Nmap against the host gives us no results. This is because the host is down, so if we ignore that with `nmap cfta-ne01.allyourbases.co -Pn`, we get the flag. We see that in my instance, port 1061 is open, so we can connect to it with `nc cfta-ne01.allyourbases.co 1061`, and get the flag `Nmap_0f_the_W0rld!`.

### NM01

This time, when we netcat to the host, we have to convert the message into the output. If you look closely, the cipher repeats itself, so we can spam the host to get the answer. `while [ 1 = 1 ]; do echo "AAAAAA" | nc cfta-nm01.allyourbases.co 8017; done` eventually gives us the flag `o[hex]=>i[ascii]=:)`.

## Web

### WE01

Copying the code that appears (by pressing Control+U / whatever it is on MacOS to view source) and executing it as JavaScript gives us the flag of `unicode+obfuscation=js*fun`.

### WE02

Opening the website, we are told that there is a secret page. A quick check to `robots.txt` gives us a path that isn't indexed: `/4ext6b6.html`. Navigating to this page gives us the flag of `Shhh_robot_you_said_too_much!`.
