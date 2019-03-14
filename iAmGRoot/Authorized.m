//
//  Authorized.m
//  iAmGRoot
//
//  Created by Dana Buehre on 2/11/19.
//  Copyright © 2019 CreatureCoding. All rights reserved.
//

#import "Authorized.h"

#include <sysexits.h>
#include <dlfcn.h>

#define FLAG_PLATFORMIZE (1 << 1)

@interface NSUserDefaults (Private)
- (void)setObject:(id)object forKey:(NSString *)key inDomain:(NSString *)domain;
@end

void authorize_as(int user, int group) {
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

@implementation Authorized

+ (void)authorizedBlock:(void (^)(void (^_Nonnull)(void)))block {
	int user	= getuid();
	int group	= getgid();
	
	authorize_as(0, 0);
	
	dispatch_semaphore_t sem = dispatch_semaphore_create(0);
	
	void (^_Nonnull completionHandler)(void) = ^{
		dispatch_semaphore_signal(sem);
	};
	
	^{@autoreleasepool{block(completionHandler);}}();
	
	dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
	
	authorize_as(user, group);
}

+ (void)authorizeAsRoot {
	[Authorized authorizeAsUser:0 group:0];
}

+ (void)authorizeAsUser:(int)user group:(int)group {
	
	NSNumber *current_user	= [NSNumber numberWithInt:getuid()];
	NSNumber *current_group	= [NSNumber numberWithInt:getgid()];
	
	if (current_user.intValue == user && current_group.intValue == group) return;
	
	authorize_as(user, group);

	[NSUserDefaults.standardUserDefaults setObject:current_user forKey:@"user"];
	[NSUserDefaults.standardUserDefaults setObject:current_group forKey:@"group"];
}

+ (void)restore {
	
	NSNumber *user = [NSUserDefaults.standardUserDefaults valueForKey:@"user"];
	NSNumber *group = [NSUserDefaults.standardUserDefaults valueForKey:@"group"];
	
	NSAssert(user != nil || group != nil, @"iAmGRoot ERROR: you need to authorize before you can restore");
	
	if (user.intValue == getuid() && group.intValue == getgid()) return;
	
	authorize_as(user.intValue, group.intValue);
	
	[NSUserDefaults.standardUserDefaults removeObjectForKey:@"user"];
	[NSUserDefaults.standardUserDefaults removeObjectForKey:@"group"];
}

@end
