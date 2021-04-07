# National Cyber Scholarship Competition Writeup

For this CTF, I used [Rizin](https://rizin.re/) for binary analysis / editing and a disposable Kali VM for running suspicious programs.

## Binary

### BE01

Downloading the PDF and running binwalk on it gives us a zip file embedded in the PDF. Extracting the zip from the PDF with `binwalk --dd='.*' chicken.pdf` gives us another ZIP file. Extracting the nested ZIP files finally gives us another PDF with the flag: `wh1ch_came_f1rst?`.

### BE02

This one is a simple overflow stack smash. Spamming `a` roughly a hundred times in the input of the program gives us the flag of `luckyNumber13`.

### BM01

This one appears to be in Russian. The question asks "what is the password?". So, lets figure out the password. Running `rz-bin -z program` gives us the list of strings used in the program. Let's try them out one by one. The first one, `молоток123` is the password, and we get the flag of `wh1te%BluE$R3d`.

### BM02

Running the program gives us no usable output. It even appears to be taunting us! This simply won't do. Let's open up the disassembly and see what is going on in the background. I opened this with the `-w` flag so we can edit the file from Rizin.

```
           ; DATA XREF from entry0 @ 0x5bd
┌ int main (int argc, char **argv, char **envp);
│           ; var uint32_t var_4h @ rbp-0x4
│           0x000007e3      push  rbp
│           0x000007e4      mov   rbp, rsp
│           0x000007e7      sub   rsp, 0x10
│           0x000007eb      mov   dword [var_4h], 1
│           0x000007f2      cmp   dword [var_4h], 0x539
│       ┌─< 0x000007f9      jne   0x807
│       │   0x000007fb      mov   eax, dword [var_4h]
│       │   0x000007fe      mov   edi, eax
│       │   0x00000800      call  sym.printFlag
│      ┌──< 0x00000805      jmp   0x813
│      ││   ; CODE XREF from main @ 0x7f9
│      │└─> 0x00000807      lea   rdi, str.I_m_not_going_to_make_it_that_easy_for_you. ; 0x8a8 ; "I'm not going to make it that easy for you." ; const char *s
│      │    0x0000080e      call  sym.imp.puts                         ; int puts(const char *s)
│      │    ; CODE XREF from main @ 0x805
│      └──> 0x00000813      mov   eax, 0
│           0x00000818      leave
└           0x00000819      ret
```

A quick look at the program shows us that it is setting a variable `var_4h` to 1, then checking if it is the value at `0x539`. Naturally, this is going to fail. How do we fix this? Simple, with patching. I am using Rizin for this, but the same instructions can be applied to Radare2. First, we have to open up visual mode with `V` (enter), and switch to the disassembly view with `p`. Looking at the comment, we have `var uint32_t var_4h @ rbp-0x4`. This is important for later. "Scroll" down to the line we want to patch at `0x7eb` and press `A`. This will put us into edit mode, and we can directly type in the Assembly code. However, if we want to just replace the `1` with `0x539`, then we can't just type in `mov dword [var_4h], 0x539`. That won't work, if you tried it out. What we need to do is to replace the variable reference with the actual register. That is what the comment earlier was for. So, in our case, the code would look like so: `mov dword [rbp-0x4], 0x539`. You ought to see the hex being automatically generated. Pressing enter and later `y` when prompted will save the changes you have made. Running the patched program gives us the flag: `patchItFixIt`.

### BM03

Opening this file in Rizin gives us the following disassembly of the main function:

```
; DATA XREF from entry0 @ 0x69d
            ;-- main:
┌ int dbg.main (int argc, char **argv, char **envp);
│           ; var int rows @ rbp-0x8
│           ; var int cols @ rbp-0x4
│           0x000008cd      push  rbp                                  ; flag.c:29 ; int main();
│           0x000008ce      mov   rbp, rsp
│           0x000008d1      sub   rsp, 0x10
│           0x000008d5      mov   rax, qword [obj.stdout]              ; flag.c:30 ; obj.__TMC_END
│                                                                      ; [0x202010:8]=0
│           0x000008dc      mov   rdi, rax                             ; FILE *stream
│           0x000008df      call  sym.imp.fflush                       ; int fflush(FILE *stream)
│           0x000008e4      lea   rdi, str.e_36m_Flag:_e_0m            ; flag.c:32 ; 0x11f8 ; "\n\x1b[36m Flag:\x1b[0m" ; const char *s
│           0x000008eb      call  sym.imp.puts                         ; int puts(const char *s)
│           0x000008f0      mov   dword [rows], 2                      ; flag.c:34
│           0x000008f7      mov   dword [cols], 0x55                   ; flag.c:35 ; 'U'
│           0x000008fe      mov   edx, dword [cols]                    ; flag.c:37
│           0x00000901      mov   eax, dword [rows]
│           0x00000904      mov   esi, edx
│           0x00000906      mov   edi, eax
│           0x00000908      call  dbg.output
│           ; DATA XREF from dbg.main @ 0x8e4
│           0x0000090d      mov   eax, 0
│           0x00000912      leave                                      ; flag.c:38
└           0x00000913      ret
```

To simplify, what is happening here is that the function `output` is being called with two arguments: 2, and 0x55. Let's figure out what's going on in that function. (I've truncated this to the relavant section).

```
0x0000088f      mov   eax, dword [i]
│      ╎    0x00000895      cmp   eax, dword [rows]
│      └──< 0x0000089b      jl    0x807
│           0x000008a1      cmp   dword [rows], 5                      ; flag.c:23
│       ┌─< 0x000008a8      jg    0x8b6
│       │   0x000008aa      lea   rdi, str.e_31m_Error_displaying_rest_of_flag_e_0m ; flag.c:24 ; 0x9c0 ; const char *s
```

Here is our error message. It checks if the `rows` argument (the first one) is less than or equal to five, then gives us the error message. So, we have to run the function with a different argument. How do we do that? Simple, we use [GDB](https://www.gnu.org/software/gdb/). Opening the program in GDB with `gdb ./flag` and setting a breakpoint at the main function with `break main` gives us a base to work on the program. Next, we have to run the actual function. Thanks to [bestredteam's blog post](https://bestestredteam.com/2020/05/01/calling-functions-with-gdb/) on calling functions, all we have to run is `print (void) output (6, 0x55)`. We have the flag: `debugging_ftw`.

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

### FM01

Opening the image, we are confronted with rainbow vomit. This is just a distraction. If you open the metadata of the image, the flag is there under `photoshop:TextLayers[1]/photoshop:LayerName`: `tr4il3r_p4rk`.

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

### WM02

Opening the website and reading through the JavaScript, it appears that we are authorized by the hash of the username and user id combined and reversed. So, we know what the hash function is, and by re-pasting most of the JavaScript into the console and hashing with the username of admin and user id of zero (just a hunch), we are able to log in and get the flag of `epoch_wizard`.
