# MShadowVEH
Shellcode execution via msedge's VEH on exit

Simple PoC that shows how registered VEHs can be abused for shellcode execution (Win10/Win11).

Since msedge.exe is a stupid program that causes some exceptions on exit, it can be abused pretty easily.

![image](https://github.com/mannyfred/MShadowVEH/assets/113118336/e37e28fd-ae67-40d3-a1d6-94d7a163d4e2)

The pointer to the VEH handler function that msedge registers is overwritten with a pointer to mapped memory.
Once an exception occurs, msedge starts looking for a handler. 

Since VEH > SEH, and we are overwriting the pointer to the first VEH handler, other handlers are completely blocked.

Msedge on Windows 11 is just disgusting:

![image](https://github.com/mannyfred/MShadowVEH/assets/113118336/2ef9d60b-3dc6-48df-9c4c-6c8bb2861f6f)



https://github.com/mannyfred/MShadowVEH/assets/113118336/26003a8e-8525-436c-b1ad-0534d510b7f6



When using a C2/revshell payload, it will only execute once. This is because calc payloads just pop a calc (with WinExec or something), and instantly return. 
This basically means that in the case of multiple exceptions, the "VEH" handler doesn't get clogged, and calc pops X times.



https://github.com/mannyfred/MShadowVEH/assets/113118336/354c0904-365e-4248-9477-bd1db1a2afa6



 
## I am living in your walls

One cool trick is that even when you completely nuke msedge, a revshell will hold on for dear life



https://github.com/mannyfred/MShadowVEH/assets/113118336/94390783-efeb-41d8-a813-0aa72010422c



### Acknowledgements
- @DimitriFourny [Dumping VEH on Win10](https://dimitrifourny.github.io/2020/06/11/dumping-veh-win10.html)
- @Ollie.Whitehouse [Detecting Anomalous VEH Handlers](https://research.nccgroup.com/2022/03/01/detecting-anomalous-vectored-exception-handlers-on-windows/)
- @Maldev-Academy (@mrd0x, @NUL0x4C, @Cracked5pider) [Maldev Academy](https://maldevacademy.com/)
