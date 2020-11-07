# --------------------------FORENSICS---------------------------
> ## Author: St1rr1ng 

![screenshoot](https://cnsc.uit.edu.vn/blog/media/2020/06/Untitled-1.png)


## Forensics Concept :
- [Forensics](https://trailofbits.github.io/ctf/forensics/): Có thể bao gồm phân tích định dạng tệp, ghi mật mã, phân tích kết xuất bộ nhớ hoặc phân tích thu thập gói mạng. Bất kỳ thách thức nào để kiểm tra và xử lý một phần thông tin ẩn trong các tệp dữ liệu tĩnh (trái ngược với các chương trình thực thi hoặc máy chủ từ xa) có thể được coi là một thách thức của Pháp y.`
 
 
## Tools:
 `split, pdfinfo, pdfimages, pdfcrack, pdfdetach, Keepass, Magic Numbers, hexed.it, foremost, binwalk, Repair image online tool, photorec, TestDisk, pngcheck, pngcsum, Registry Dumper, Dnscat2, pefile, Wireshark, Network Miner, PCAPNG, tcpflow, PcapXray, qpdf, Audacity, sonic visualiser, ffmpeg strings, file, grep, scalpel, bgrep, hexdump, xxd, base64, xplico framework, zsteg, gimp, Memory dump - volatility, ethscan, and many more.`
 - [stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)
 
 
> # Sau đây mình sẽ chia sẽ một số EX cho các bạn chơi mảng Forensics theo từng dạng thông qua các challenges mình đã giải: 
 
 # *1. Image file format analysis*
 * [Link download Challange](https://github.com/minhgalaxy/WannaGame2/blob/master/Forensic/130e423cf6ea37874a01ae502bfff92n.jpg?raw=true)
 
 ![screenshoot](https://scontent.xx.fbcdn.net/v/t1.15752-0/p280x280/123661023_398977774844203_3032350174838271212_n.png?_nc_cat=102&ccb=2&_nc_sid=ae9488&_nc_ohc=dPfZ7OUV48gAX-okMYV&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=5d5a842b8f5896f70a2e112576b1502d&oe=5FCDB5DE)
 
 * Thông thường khi gặp những bài này ta sẽ dùng ``` binwalk ``` xem nó file gì bị nén trong đó hay không.
 
 ![screenshoot](https://scontent.xx.fbcdn.net/v/t1.15752-9/123311082_642402783097986_428877093019192757_n.png?_nc_cat=100&ccb=2&_nc_sid=ae9488&_nc_ohc=0YDzFDP0jLIAX8aZARD&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=088ecce3ed4df4459b194665f792235f&oe=5FCAF94F)
 
 * Sau khi kiểm tra ta thấy nó có chứa file PDF trong ảnh. Ta dùng lệnh ``` binwalk --dd='.*' wallet.jpeg ``` để extract file bị ẩn
 
 ![screenshoot](https://scontent.fsgn2-5.fna.fbcdn.net/v/t1.15752-9/123656381_879225516215622_8180720782504705366_n.png?_nc_cat=104&ccb=2&_nc_sid=ae9488&_nc_ohc=bzNN-Oa1j2AAX-H5z9t&_nc_ht=scontent.fsgn2-5.fna&oh=84cd24d59e3a504dc23d27c788d35661&oe=5FCCFF16)
 
 * Ta được file ``` _wallet.jpg.extracted ``` . Sau đó check file ta thấy có 2 file ` 0 ` và ` 2E11E `
 * Ta sẽ đổi đuôi file ` 2E11E ` thành `.pdf `
 
 ![screenshoot](https://scontent.fsgn2-5.fna.fbcdn.net/v/t1.15752-9/123696583_425752171753268_7163555969361567092_n.png?_nc_cat=106&ccb=2&_nc_sid=ae9488&_nc_ohc=yY_X3kwBXu0AX8VB-AJ&_nc_ht=scontent.fsgn2-5.fna&oh=60e44fd75a6f56f60d221d20d4808bde&oe=5FCC24FB)
 
 * Xem file PDF ta thấy ngay Flag ở trang 23 :D
 
 ![screenshoot](https://scontent.fsgn2-2.fna.fbcdn.net/v/t1.15752-9/123571834_728857287837642_2997043308238732273_n.png?_nc_cat=103&ccb=2&_nc_sid=ae9488&_nc_ohc=kT-FnfaABBAAX_rkNKB&_nc_ht=scontent.fsgn2-2.fna&oh=df183da78f0c1220a3ccc0a29043457b&oe=5FCAA875)
 
 > ## Flag: flag(m0r3_v4lu4bl3_th4n_y0u_th1nk)

 
 # 2. Network Forensics
 ## Challenge:
 
 > We found this [packet capture](https://l.facebook.com/l.php?u=https%3A%2F%2Fcdn.fbsbx.com%2Fv%2Ft59.2708-21%2F70187595_2519734864751326_2446784547170287616_n.pcap%2Fcapture.pcap%3F_nc_cat%3D110%26ccb%3D2%26_nc_sid%3D0cab14%26_nc_ohc%3Db2BXtfRiTW4AX-_ghIL%26_nc_ht%3Dcdn.fbsbx.com%26oh%3D8410a081aae8b0c5d6ccdd670cdd4f3f%26oe%3D5FA81CFC%26dl%3D1&h=AT1_GmH9wPEsbbY4M9Opx6yNZtn-zd8alqiMoLC4DcA1fNZwXV81JJCUr6r1TPLr4aJni_AgCOkwmVzSXmYZRZJTtkVCdnCjgKJUrESRY1YBvwHDuxbdpQrQjzw8PQZRoDAVjdeV06iRUb63bkr8Z4PhZ8I&s=1) Recover the flag. You can also find the file in /problems/shark-on-wire-1_0_13d709ec13952807e477ba1b5404e620.
 
* Để làm các bài `.pcap` các bạn cần sử dụng WireShark.
Các bạn có thể tìm hiểu công cụ WireShark [ở đây](https://quantrimang.com/su-dung-wireshark-de-phan-tich-goi-du-lieu-trong-he-thong-mang-85026)

* Đầu tiên ta mở file bằng WireShark 

![screenshoot](https://scontent.xx.fbcdn.net/v/t1.15752-0/p280x280/123506683_3470973512988430_3934017401238069891_n.png?_nc_cat=108&ccb=2&_nc_sid=ae9488&_nc_ohc=qlA231G9EscAX_C7yEP&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=a4507e7ca6f775fa39210ff1e77f8b66&oe=5FCC46C0)

* Theo dõi cấc luồng UDP bằng cách nhấn chuột phải vào UPD chọn `Follow UDP Stream`
* Sau đó nâng mức Stream lên 6 ta sẽ có ngay Flag

![screenshoot](https://scontent.xx.fbcdn.net/v/t1.15752-0/p280x280/123691094_360042441739660_4343655527030408502_n.png?_nc_cat=102&ccb=2&_nc_sid=ae9488&_nc_ohc=5hRR4JY6giUAX_DsQDc&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=19ca716924aa01901eb8a54207363853&oe=5FCA208E)

> # Flag: picoCTF{StaT31355_636f6e6e}


# 3. File header analysis

> NaCTF Turnips 2

![screenshoot](https://scontent.xx.fbcdn.net/v/t1.15752-0/p280x280/123702543_669545483752770_2845514726298493906_n.png?_nc_cat=111&ccb=2&_nc_sid=ae9488&_nc_ohc=cNDksU9edooAX9kph1a&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=0afca8bca76f79ac4927514475886921&oe=5FCD6F92)

[Link download challenges](https://www.nactf.com/files/c59d577c159f97c6903f4edcf23c97e0/file.txt?token=eyJ1c2VyX2lkIjoxMjQ1LCJ0ZWFtX2lkIjo3ODksImZpbGVfaWQiOjN9.X6YS9w.aFuHba25aX5Mfd98Pv4CL8dG_lo)

`HINT`: File headers are important, aren't they?

* Hint đã nói quá rõ việc ta cần làm, kiểm tra File headers bằng ``` hexedit ``` thôi

``` kali@kali:~/Desktop/CTF$ hexedit file.txt ```

![screenshoot](https://scontent.xx.fbcdn.net/v/t1.15752-0/p280x280/123613973_434514974201294_7504151843897314040_n.png?_nc_cat=107&ccb=2&_nc_sid=ae9488&_nc_ohc=etVivtbBX8UAX_TYKOW&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=cfcdddca811e42b89e1cfbc222badbe5&oe=5FCC8BBC)

* Ta thấy 8 byte đầu header của file sai định dạng. Tham khảo [trang này](https://digital-forensics.sans.org/media/hex_file_and_regex_cheat_sheet.pdf) ta sửa 8 byte đầu thành PNG `89 50 4E 47` và đổi tên file thành `.png`

![screenshoot](https://scontent.xx.fbcdn.net/v/t1.15752-0/p280x280/123802084_1104100316672032_7476042269732742376_n.png?_nc_cat=106&ccb=2&_nc_sid=ae9488&_nc_ohc=eRUruU5jh1wAX_wP1B8&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=c8eea1280db8385c108af88e6c08556a&oe=5FCA0DEE)

* Nhiều khi điều ta nghĩ lại không như ta nghĩ :D Sau khi mở ```file.png``` để xem flag thì hiện lên dòng yêu thương ```Could not load image “file.png”``` 
* Sau khi check laị header và tham khảo trang thần thánh [StackOverFlow](https://stackoverflow.com/questions/54845745/not-able-to-read-ihdr-chunk-of-a-png-file) thì mình phát hiện lại cái ```chunk IHDR``` nó cố ý làm sai nên sửa lại luôn.

![screenshoot](https://scontent.xx.fbcdn.net/v/t1.15752-0/p280x280/124091651_291482308678641_857464140824961108_n.png?_nc_cat=109&ccb=2&_nc_sid=ae9488&_nc_ohc=RMhiZKKL_NcAX_0pngW&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=7fc0ba2b40ca6c894ba8cf89a013cfa1&oe=5FCCDD99)

* Check lại file xem nào. Ohhh Flag đây rồi :D
 
![screenshoot](https://scontent.xx.fbcdn.net/v/t1.15752-0/p280x280/123768827_989066564947840_5410629465670528202_n.png?_nc_cat=102&ccb=2&_nc_sid=ae9488&_nc_ohc=g1dYX7ZuLIsAX-37YIv&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=83fa905aa9c3105fb3c7d15fc7f9996d&oe=5FCB2E42)

> ## *Flag:* nactf{th3_turn1p5_ar3_tak17g_0v35_skf9}

#  4. Sound File

> Can you find flag? 
> [sound.wav](https://sites.google.com/site/hyp3rn/home/attachments/sound.wav?attredirects=0&d=1)

* Một bài đơn giản về âm thanh. Để tìm Flag ta chỉ cần cho file này vào [Audacity](https://www.audacityteam.org/?__cf_chl_captcha_tk__=e7cfd4d4dadd6a4bcae439b6716d4ca993944124-1604727733-0-ATKpHjgBe1dvGRUcOFrwfFUpOC9exkjt7ez4RldVQ-ceg19Sajjc0y3TsKi8Xo91oARN8JTpTEJOBdxTq261Jf8-Vd1ZesRba2rSDJu1vMgj7o36_2FFSYXuHu3x5RlYENXUPkSxloEYT-vTJ6P2rZEnkaKO2-5HAHncjgGBnxsuiZT4bZiZRTxLvqc_hbzMQcMbduwxXiBgmXp1JQsinN1923MrjiQRbmDHXVYJFxnk3fE6LufK4ZXx_3nL-YD8AUla5WPDbqCgBEYpA5fSTEFzo31Cn7f6Vt3YhHMjnsN7yPQLIpUSo847d8iXOORh76PB3PdXPEhLocCc_xJ8TqSWM7ED7KGfJK88czZGSAQKztlWqKtza-54ohCHtndTjcaVB4zw25DQPC1x2C3M0V6Vr_LisnwIelDsQTy7WfJ2ayOKbEiDjuI2hyZ5tmouWwCvGOMk7fFf7tGDnfGkaGzegXfcH7cFOaJdw0hYRdw6sL5y_xEB653lLiNf8uBKHaId8CfEzzrkzH31AbYCql6lq5RUs0mXkqb8LTl9ovb1)

![screenshoot](https://scontent.xx.fbcdn.net/v/t1.15752-0/p280x280/124171559_985549701943545_1020421570834714928_n.png?_nc_cat=102&ccb=2&_nc_sid=ae9488&_nc_ohc=Eyx1dZksLj4AX_eiCNs&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=277569a645cc09991fb534714f8a34dc&oe=5FCC6C6E)

* `Sound` đang ở đạng `Waveform` ta chỉnh sang `Spectrogram` là ra flag

![screenshoot](https://scontent.xx.fbcdn.net/v/t1.15752-0/p280x280/123571539_362249081768757_5934406091159703082_n.png?_nc_cat=111&ccb=2&_nc_sid=ae9488&_nc_ohc=Hely5VQVUA0AX9jXInM&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=0d238ca1ea58825c894d70512e82081d&oe=5FCB4AE8)

# 5. Memory Forensics

> ## Problem description
> *  Flag is: FwordCTF{computername_user_password}
> * [foren.raw](https://drive.google.com/file/d/1mlCB4Ai6mjbzGoNEw-w1lBr-RbQ9TzPa/view?usp=sharing)

* Đối với dạng này ta ta có tool [Volatility](https://resources.infosecinstitute.com/topic/memory-forensics-and-analysis-using-volatility/) để giải quyết

* Làm gì thì làm extract file trước đã kkk :D

* Dùng `Volatility` để lấy thông tin file:

 ```sh
 $ volatility -f foren.raw imageinfo
 Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
AS Layer2 : FileAddressSpace (/home/jeanette/Downloads/foren.raw)

```
* Để có thông tin về tên máy tính, chúng ta cần thông tin về REGISTRY \ MACHINE \ SYSTEM. Để lấy băm tên người dùng và mật khẩu, chúng tôi cần thông tin về REGISTRY \ MACHINE \ SYSTEM và \ SystemRoot \ System32 \ Config \ SAM.

* Giờ ta bắt đầu tìm mảnh ghép Flag
 
  # ComputerName 
 
* Để lấy `ComputerName`, chúng ta có thể sử dụng lệnh sau (đối số -o là một tham chiếu đến địa chỉ ảo của \ REGISTRY \ MACHINE \ SYSTEM):
 
 ```sh
 $ volatility -f foren.raw --profile=Win7SP1x64 printkey -o 0xfffff8a000024010 -K 'ControlSet001\Control\ComputerName\ComputerName'
    REG_SZ        ComputerName    : (S) FORENWARMUP*
 ```
 > ## Ta có ngay Computername: FORENWARMUP
 
  # User
 
* Để biết user ta chỉ cần dùng lệnh `envars` và `grep` như sau:

```sh
$ volatility -f foren.raw --profile=Win7SP1x64 envars | grep 'C:\\Users'
Volatility Foundation Volatility Framework 2.6
Pid      Process              Block              Variable                       Value
-------- -------------------- ------------------ ------------------------------ -----
2516 chrome.exe           0x0000000000a31320 USERPROFILE                    C:\Users\SBA_AK
3992 chrome.exe           0x0000000000931320 APPDATA                        C:\Users\SBA_AK\AppData\Roaming
3992 chrome.exe           0x0000000000931320 LOCALAPPDATA                   C:\Users\SBA_AK\AppData\Local
```
> ## Như vậy ta có User: SBA_AK

 # Password
* Bước tiếp theo mình cũng làm theo hướng dẫn sau để thực hiện tìm password: [Retrieve-password](https://www.aldeid.com/wiki/Volatility/Retrieve-password)

```sh
volatility -f foren.raw --profile=Win7SP0x64 hivelist
Volatility Foundation Volatility Framework 2.6
Virtual            Physical           Name
------------------ ------------------ ----
0xfffff8a000b0f410 0x000000002720d410 \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0xfffff8a000d00010 0x000000001ff75010 \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT
0xfffff8a000f8b410 0x00000000175e8410 \??\C:\Windows\System32\config\COMPONENTS
0xfffff8a00145f010 0x0000000027d9b010 \SystemRoot\System32\Config\DEFAULT
0xfffff8a0014da410 0x00000000275c0410 \SystemRoot\System32\Config\SAM
0xfffff8a0033fe410 0x0000000069de6410 \??\C:\Users\SBA_AK\ntuser.dat
0xfffff8a0036e7010 0x0000000069188010 \??\C:\Users\SBA_AK\AppData\Local\Microsoft\Windows\UsrClass.dat
0xfffff8a0038fe280 0x0000000068390280 \??\C:\System Volume Information\Syscache.hve
0xfffff8a00000f010 0x000000002cfef010 [no name]
0xfffff8a000024010 0x000000002d07a010 \REGISTRY\MACHINE\SYSTEM
0xfffff8a000058010 0x000000002d3ae010 \REGISTRY\MACHINE\HARDWARE
0xfffff8a000846010 0x000000002a0e9010 \Device\HarddiskVolume1\Boot\BCD
0xfffff8a000873010 0x0000000013880010 \SystemRoot\System32\Config\SOFTWARE
0xfffff8a000ab8010 0x0000000027455010 \SystemRoot\System32\Config\SECURITY
```

* Hàm băm của người dùng được lưu trữ trong \SystemRoot\System32\Config\SAM file.

```sh
volatility -f foren.raw --profile=Win7SP0x64 hashdump -y 0xfffff8a000024010 -s 0xfffff8a0014da410
Volatility Foundation Volatility Framework 2.6
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
fwordCTF:1000:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:514fab8ac8174851bfc79d9a205a939f:::
SBA_AK:1004:aad3b435b51404eeaad3b435b51404ee:`a9fdfa038c4b75ebc76dc855dd74f0da`:::

```
* Và đó là cách mình lấy tên người dùng và mã băm NTLM của mật khẩu của họ cần được bẻ khóa.

* Mình đã bẻ khóa mật khẩu của anh ấy bằng [https://crackstation.net/](https://crackstation.net/)

![screenshoot](https://scontent.xx.fbcdn.net/v/t1.15752-0/p280x280/123801113_716021899046105_8085850621298664560_n.png?_nc_cat=106&ccb=2&_nc_sid=ae9488&_nc_ohc=_MJBM69hXWMAX-uFHSL&_nc_ad=z-m&_nc_cid=0&_nc_ht=scontent.xx&oh=de284ae239bc587d3d304c91c6a434f7&oe=5FCB1506)

> ## Và mảnh ghép cuối cùng Password: password123

> # Flag: FwordCTF{FORENWARMUP_SBA_AK_password123}

# TỔNG KẾT:
* Đây chỉ là những challenges đơn giản mà mình đã tổng hợp để các bạn có thể hiểu sơ qua những gì mà khi chơi mảng Forensics phải làm.
* Và từ những cái cơ bản này các bạn có thể đi sâu hơn để trở thành Main Forensics nhé.
* Con đường nào cũng phải cần kiên trì, kết quả bạn nhận lại được sẽ tỉ lệ thuận với số lượng mồ hôi, thời gian, công sức bạn làm việc đó. CHÚC CÁC BẠN THÀNH CÔNG!






 
 
 


















 
 
