/* code remake for 10.10
 * from uninformed_v4a3
 * by nemo
 * This code will hook and write to each register replacing the value with
 * 0xdeadbeef.  To be tested with test.asm 
 * chapter 7, replacing ptrace
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <unistd.h>

void print_regs(x86_thread_state64_t intel_state);

void error(char *msg)
{
	printf("[!] error: %s.\n", msg);
	exit(1);
}


int main(int ac, char ** av)
{

	x86_thread_state64_t intel_state;
	unsigned long* ptr;
	long thread = 0;
	unsigned int microseconds = 1000000;
	mach_msg_type_number_t sc = x86_THREAD_STATE64_COUNT; 
	thread_act_port_array_t thread_list;
	mach_msg_type_number_t thread_count;
	task_t port;
	pid_t pid;
	
	if (ac != 2) {
		printf("usage: %s <pid>\n", av[0]);
		exit(1);
	}

	pid = atoi(av[1]);

	if(task_for_pid(mach_task_self(), pid, &port))
		error("cannot get port");

	if (task_threads(port, &thread_list, &thread_count))
		error("cannot get list of tasks");

	if(thread_get_state(
		thread_list[thread],
		x86_THREAD_STATE64,
		(thread_state_t)&intel_state,
		&sc
	)) error("getting state from thread");
	
	ptr = &intel_state;

	while (1)
	{
		print_regs(intel_state);
	    //increment through the registers, deadbeefing each one
		*ptr = 0x00000000deadbeef;
		
		if(thread_set_state(
				thread_list[thread],
				x86_THREAD_STATE64,
		        (thread_state_t)&intel_state,
	 		        sc
	 	)) { error("setting state");
			break;
		}
		ptr++;

		for (int i=0; i < 50; i++){
			printf("=");

		} printf("\n");
		
		usleep(microseconds);
		
	} //end loop

	return 0;
}

void print_regs(x86_thread_state64_t intel_state){
	//address & <--
	printf("rax value: 0x%llx: \taddress 0x%llx\n", intel_state.__rax, &intel_state.__rax);
	printf("rbx value: 0x%llx: \taddress 0x%llx\n", intel_state.__rbx, &intel_state.__rbx);
	printf("rcx value: 0x%llx: \taddress 0x%llx\n", intel_state.__rcx, &intel_state.__rcx);
	printf("rdx value: 0x%llx: \taddress 0x%llx\n", intel_state.__rdx, &intel_state.__rdx);
	printf("rdi value: 0x%llx: \taddress 0x%llx\n", intel_state.__rdi, &intel_state.__rdi);
	printf("rsi value: 0x%llx: \taddress 0x%llx\n", intel_state.__rsi, &intel_state.__rsi);
	printf("rbp value: 0x%llx: \taddress 0x%llx\n", intel_state.__rbp, &intel_state.__rbp);
	printf("rsp value: 0x%llx: \taddress 0x%llx\n", intel_state.__rsp, &intel_state.__rsp);
} //end function
