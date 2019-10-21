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
	
	setruid(user);
	setruid(user);
	setrgid(group);
	
	
	if (getuid() == user && getgid() == group) { return; }
	NSLog(@"(*** iAmGRoot ***) PHASE 1 failed uid not set, attempting PHASE 2");
	
	if (getuid() != user) { seteuid(user); }
	if (getgid() != group) { setegid(group); }
	
	if (getuid() == user && getgid() == group) { return; }
	NSLog(@"(*** iAmGRoot ***) PHASE 2 failed uid not set, attempting PHASE 3");
	
	setuid(user);
	setuid(user);
	setgid(group);
	
	if (getuid() == user && getgid() == group) { return; }
	NSLog(@"(*** iAmGRoot ***) PHASE 3 failed uid not set, attempting PHASE 4");
	
	void* handle = dlopen("/usr/lib/libjailbreak.dylib", RTLD_LAZY);
	
	if (!handle) {
		NSLog(@"(*** iAmGRoot ***) ERROR %s unable to find libjailbreak.dylib", dlerror());
		NSLog(@"(*** iAmGRoot ***) ERROR failed setrid, seteid, setuid");
		return;
	}
	
	typedef void (*fix_setuid_prt_t)(pid_t pid);
	typedef void (*fix_entitle_prt_t)(pid_t pid, uint32_t what);
	fix_setuid_prt_t setuidptr 		= (fix_setuid_prt_t)dlsym(handle, "jb_oneshot_fix_setuid_now");
	fix_entitle_prt_t entitleptr 	= (fix_entitle_prt_t)dlsym(handle, "jb_oneshot_entitle_now");
	
	setuidptr(getpid());
	setuid(user);
	setuid(user);
	
	const char *dlsym_error = dlerror();
	if (dlsym_error) {
		NSLog(@"(*** iAmGRoot ***) ERROR unable to platformize (dlsym error): %s \n", dlsym_error);
		return;
	}
	
	entitleptr(getpid(), FLAG_PLATFORMIZE);
	
	if (getuid() != user) { setuid(user); }
	if (getgid() != group) { setgid(group); }
	
	if (getuid() == user && getgid() == group) { return; }
	NSLog(@"(*** iAmGRoot ***) PHASE 4 failed uid not set, dont blame me, blame the half baked jailbreak");
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
	
	if (current_user.intValue == user && current_group.intValue == group) {
		NSLog(@"(*** iAmGRoot ***) already running as efective user: (%d) and group: (%d), skipping elevation", current_user.intValue, current_group.intValue);
		return;
	}
	
	authorize_as(user, group);

	[NSUserDefaults.standardUserDefaults setObject:current_user forKey:@"iagr_user"];
	[NSUserDefaults.standardUserDefaults setObject:current_group forKey:@"iagr_group"];
}

+ (void)restore {
	
	NSNumber *user = [NSUserDefaults.standardUserDefaults valueForKey:@"iagr_user"];
	NSNumber *group = [NSUserDefaults.standardUserDefaults valueForKey:@"iagr_group"];
	
//	NSAssert(user != nil || group != nil, @"iAmGRoot ERROR: you need to authorize before you can restore");
	if (user == nil || group == nil) {
		NSLog(@"(*** iAmGRoot ***) WARNING: you need to authorize before you can restore. skipping restore");
		return;
	}
	
	if (user.intValue == getuid() && group.intValue == getgid()) {
		NSLog(@"(*** iAmGRoot ***) WARNING: current user and group are the same as the restoration user and group, skipping restore for user: (%d) group: (%d)", user.intValue, group.intValue);
		return;
	}
	
	authorize_as(user.intValue, group.intValue);
	
	[NSUserDefaults.standardUserDefaults removeObjectForKey:@"iagr_user"];
	[NSUserDefaults.standardUserDefaults removeObjectForKey:@"iagr_group"];
}

@end
