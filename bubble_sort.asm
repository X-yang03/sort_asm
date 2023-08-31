.386                                       ;使用80386指令集编写
.model flat, stdcall                        ;说明程序运行模式 使用平坦4GB内存空间，stdcall是Win32 API函数的调用约定 
option casemap :none                        ;指明大小写敏感
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc           ;函数常量的声明
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib           ;链接库

.data
str_out BYTE 10 dup(0)                      ;输出字符串
strnum BYTE 10 dup(0)                       ;输入字符串
tmp DWORD ?,0                               ;记录次数的变量
num dword 10 dup(0)                         ;数组，每个大小为dword
space dword "  ",0                          ;空格

.code
main PROC 

mov ebx,0                                  ;ebx存放偏移地址
mov tmp,10                                 ;共输入10个数据

P1:                                        ;P1循环用以输入10个数字
    CMP tmp,0
    JE P2
    invoke StdIn,addr strnum,10
    invoke atodw,addr strnum              ;调用atodw函数，eax中返回对应dword大小数据
    mov dword PTR[num+ebx],eax            ;数据存放进数组
    add ebx,20h                           ;ebx每次增加32（一个dword）
    dec tmp
    JMP P1

P2:
    mov ecx,10
    dec ecx

LOOP1:                                  ;LOOP1为外循环
    mov edx,ecx
    mov ebx,0                           ;ebx仍然存放偏移地址

LOOP2:
    mov eax,DWORD PTR [num+ebx]
    cmp eax, DWORD PTR [num+ebx+32]    ;比较相邻两数大小
    JLE P3                              ;前者不大于后者则跳至P3
    XCHG eax, DWORD PTR [num+ebx+32]
    mov dword PTR [num+ebx],eax         ;前者大于后者，则交换数据

P3:
    add ebx,32
    dec ecx                             ;次数减一
    JNE LOOP2                           ;判断内循环是否结束
    mov ecx,edx
    LOOP LOOP1                          ;LOOP时ecx会减一，edx会记录下ecx的初始值，实现外循环
    
P4:
    mov tmp,10                          ;输出10个字符串
    mov ebx,0

P5:
    mov eax,dword PTR[num+ebx]          
    invoke dwtoa,eax,addr str_out       ;调用dwtoa，转换成字符串存至str_out
    ;mov tmp,eax
    invoke StdOut,addr str_out
    invoke StdOut,addr space            ;输出字符串与空格
    add ebx,32                          ;ebx存放偏移地址，每次加32
    dec tmp                         
    cmp tmp,0
    JNE P5                              ;条件判断

invoke ExitProcess, 0
main ENDP
END main