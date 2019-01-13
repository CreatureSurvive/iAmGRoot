#ifndef Privileged_h
#define Privileged_h

@interface Privileged : NSObject

/*
// usage:	[Privileged privilagedBlock:^(void (^_Nonnull completionHandler)()) {
//				// run your code here
//				// once your done invoke completion
//				completionHandler();
//			}];
*/
+ (void)privilegedBlock:(void (^)(void (^_Nonnull)()))block;

@end

#endif /* privilaged_h */

/*

detailed usage:

in the makefile add:
$(TWEAK_NAME)_EXTRA_FRAMEWORKS = iAmGRoot

in your class:

#import <myClass.h>
#import <Privileged.h>

@implementation myClass

- (void)viewDidLoad {
	[super viewDidLoad];
	
	[Privileged privilagedBlock:^(void (^_Nonnull completionHandler)()) {
		// run your code here
		NSStirng *str = [someClass someMethodThatRequiresRoot];
		// once your done invoke completion
		completionHandler();
	}];
}

@end

*/