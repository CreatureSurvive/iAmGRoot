#include <Privileged.h>
#include <dlfcn.h>
#include <sysexits.h>
#include <Foundation/Foundation.h>

#define FLAG_PLATFORMIZE (1 << 1)
#define LOG2FILE = 1

void platformize(int user, int group) {
	setuid(user);
	setgid(group);

	if (getuid() == user) { return; }
	
	void* handle = dlopen("/usr/lib/libjailbreak.dylib", RTLD_LAZY);

	if (!handle) {
		printf("Err: %s \nunable to find libjailbreak.dylib\n", dlerror());
		return;
	}

	typedef void (*fix_setuid_prt_t)(pid_t pid);
	typedef void (*fix_entitle_prt_t)(pid_t pid, uint32_t what);
	fix_setuid_prt_t setuidptr 		= (fix_setuid_prt_t)dlsym(handle, "jb_oneshot_fix_setuid_now");
	fix_entitle_prt_t entitleptr 	= (fix_entitle_prt_t)dlsym(handle, "jb_oneshot_entitle_now");

	setuidptr(getpid());
	setuid(user);

	const char *dlsym_error = dlerror();
	if (dlsym_error) {
		 printf("encountered dlsym error: %s \n", dlsym_error);
		return;
	}

	entitleptr(getpid(), FLAG_PLATFORMIZE);
	
	if (getuid() != user) { setuid(user); }
}

@implementation Privileged : NSObject

+ (void)privilegedBlock:(void (^)(void (^_Nonnull)()))block {
	int user	= getuid();
	int group	= getgid();
	
	platformize(0, 0);
	
	dispatch_semaphore_t sem = dispatch_semaphore_create(0);
	
	void (^_Nonnull completionHandler)() = ^{
		dispatch_semaphore_signal(sem);
	};
	
	^{@autoreleasepool{block(completionHandler);}}();
	
	dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
	
	platformize(user, group);
}

@end