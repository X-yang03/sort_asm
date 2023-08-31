.386
.model flat,stdcall
option casemap:none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib
includelib \masm32\lib\debug.lib

include \masm32\include\user32.inc
includelib \masm32\lib\user32.lib

.data
filehandle DWORD 0  ;运行模块句柄
tip1 BYTE "PLEASE INPUT A PE FILE:",0
space BYTE "     ",0
IDH BYTE "IMAGE_DOS_HEADER:",0
INH BYTE  "IMAGE_NT_HEADER:",0
IFH BYTE "IMAGE_FILE_HEADER:",0
IOH BYTE "IMAGE_OPTIONAL_HEADER:",0
em BYTE "e_magic:",0
el BYTE "e_lfanew:",0
sig BYTE "Signature:",0
NOS BYTE "NumberOfSections:",0
TDS BYTE "TimeDataStamp:",0
chara BYTE "Characteristic:",0
AOEP BYTE "AdressOfEntryPoint",0
IB BYTE "ImageBase:",0
SA BYTE "SectionAlignment:",0
FA BYTE "FileAligment:",0
endline BYTE 0ah,00h

file BYTE 5000 dup(0) ;保存模块数据
fileBase DWORD ? ;程序运行的基地址
var DWORD ?
tmp  BYTE "00000000",0;输出值
buf dword 100 dup(0)
filename BYTE 20 dup(0)  ;pe文件名

.code
main PROC
invoke StdOut,addr tip1
invoke StdIn,addr filename,20
invoke CreateFile,addr filename,\      ;打开path所指对象，并返回访问对象的句柄
                              GENERIC_READ,\
                              FILE_SHARE_READ,\
                              0,\
                              OPEN_EXISTING,\
                              FILE_ATTRIBUTE_ARCHIVE,\
                              0

mov filehandle,eax     ;filehandle记录句柄

invoke SetFilePointer,filehandle,\
                                  0,\
                                  0,\
                                  FILE_BEGIN   ;移动文件指针至开头

invoke ReadFile,filehandle,\
                           addr file,\
                           4900,\
                           0,\
                           0          ;从指定文件读取数据

mov esi,OFFSET file    
;将运行模块基地址写入esi 

mov eax,0h
invoke StdOut,addr IDH    ;IMAGINE_DOS_HEADER：
invoke StdOut,addr endline
invoke StdOut,addr space    ;缩进
invoke StdOut,addr em    ;e_magic：

mov fileBase,esi           ;fileBase记录文件基地址
mov eax,DWORD ptr[esi]     ;读取esi处dword大小数据
invoke dw2hex,eax,addr tmp ;调用dw2hex将读取到的16进制数据转换成字符串
mov eax,dword ptr[tmp+4]   ;如果只输出4位字符串则需要此操作
mov buf,eax
invoke StdOut,addr buf      ;打印e_magic

add esi,3ch               ;此时esi存储e_lfanew的地址
invoke StdOut,addr endline
invoke StdOut,addr space;换行
invoke StdOut,addr el     ;e_lfanew:
mov eax,DWORD ptr[esi]    ;读取esi保存地址处的数据
invoke dw2hex,eax,addr tmp   ;dw2hex转换成字符串
invoke StdOut,addr tmp    ;输出字符串，以下将重复此操作，不断读数据并转换成字符串输出，不进行重复注释


mov eax,dword ptr[esi]
add eax,fileBase             ;获得pe文件头绝对地址
mov esi,eax
invoke StdOut,addr endline   ;换行
invoke StdOut,addr INH     ;IMAGE_NT_HEADER:
invoke StdOut,addr endline   ;
invoke StdOut,addr space     
invoke StdOut,addr sig     ;Signature:

mov eax,DWORD ptr[esi]      ;读出pe文件头NTHEADER，即PE..，十六进制为00004550
invoke dw2hex,eax,addr tmp
invoke StdOut,addr tmp

invoke StdOut,addr endline
invoke StdOut,addr IFH     ;IMAGE_FILE_HEADER
invoke StdOut,addr endline
invoke StdOut,addr space    
invoke StdOut,addr NOS     ;NumberOfSections

add esi,6h                   ;NumberOfSections相对IMAGE_FILE_HEADER的偏移地址为06h
mov eax,DWORD ptr[esi]
invoke dw2hex,eax,addr tmp
mov eax,dword ptr[tmp+4]
mov buf,eax
invoke StdOut,addr buf           ;打印NOS
invoke StdOut,addr endline

add esi,2h                 ;TimeDataStamp相对NOS的偏移地址为2h
invoke StdOut,addr space
invoke StdOut,addr TDS    ;TimeDataStamp:
mov eax,DWORD ptr[esi]     ;读出TDS值
invoke dw2hex,eax,addr tmp
invoke StdOut,addr tmp
invoke StdOut,addr endline

add esi,0eh               ;Characteristics相对TDS偏移地址为0eh
invoke StdOut,addr space
invoke StdOut,addr chara  ;Characteristics:
mov eax,DWORD ptr[esi]
invoke dw2hex,eax,addr tmp
mov eax,dword ptr[tmp+4]
mov buf,eax
invoke StdOut,addr buf
invoke StdOut,addr endline
invoke StdOut,addr IOH     ;IMAGE_OPTIONAL_HEADER
invoke StdOut,addr endline

add esi,12h               ;AddressOfEntryPoint相对Cha...偏移地址为12h（28h-18h+18h-16h）
invoke StdOut,addr space
invoke StdOut,addr AOEP  ;AddressOfEntryPoint:
mov eax,DWORD ptr[esi]    ;大小为一个DWORD
invoke dw2hex,eax,addr tmp
invoke StdOut,addr tmp
invoke StdOut,addr endline

add esi,0ch     ;ImageBase相对AOEP偏移och（34h-28h）
invoke StdOut,addr space
invoke StdOut,addr IB ;ImageBase:
mov eax,DWORD ptr[esi]
invoke dw2hex,eax,addr tmp
invoke StdOut,addr tmp
invoke StdOut,addr endline

add esi,4h         ;SectionAlignment相对IB偏移4h
invoke StdOut,addr space
invoke StdOut,addr SA  ;SectionAlignment:
mov eax,DWORD ptr[esi]
invoke dw2hex,eax,addr tmp
invoke StdOut,addr tmp
invoke StdOut,addr endline

add esi,4h              ;FileAliment相对SA偏移4h（3ch-38h）
invoke StdOut,addr space
invoke StdOut,addr FA   ;FileAlignment:
mov eax,dword ptr[esi]
invoke dw2hex,eax,addr tmp
invoke StdOut,addr tmp   

invoke StdOut,addr endline
invoke CloseHandle,filehandle
invoke ExitProcess,0
main ENDP
END main


