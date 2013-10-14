//
//  iSXMAnalysisModule.h
//  iOScanX Module
//
//  Created by Alessio Maffeis on 17/06/13.
//  Copyright (c) 2013 Alessio Maffeis. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <ScanX/SXModule.h>
#import "iSXApp.h"

@interface iSXMMemoryProtection : NSObject <SXModule>

@property (readonly) BOOL readonly;

- (BOOL) itemIsValid:(iSXApp*)item;
- (NSString*) temporaryItem:(iSXApp*)item;
- (BOOL) deleteItem:(iSXApp*)item;

@end
