//
//  iSXMAnalysisModule.m
//  iOScanX Module
//
//  Created by Alessio Maffeis on 17/06/13.
//  Copyright (c) 2013 Alessio Maffeis. All rights reserved.
//

#import "iSXMMemoryProtection.h"
#import "NSFileManager+DirectoryLocations.h"

@implementation iSXMMemoryProtection {
    
    NSString *_bundleIdentifier;
    NSString *_tmpPath;
}

@synthesize delegate = _delegate;
@synthesize name = _name;
@synthesize prefix = _prefix;
@synthesize metrics = _metrics;

- (id) init {
    
    self = [super init];
    if (self) {
        NSBundle *bundle = [NSBundle bundleForClass:[iSXMMemoryProtection class]];
        NSString *plist = [bundle pathForResource:@"Module" ofType:@"plist"];
        NSDictionary *moduleInfo = [NSDictionary dictionaryWithContentsOfFile:plist];
        _name = [[NSString alloc] initWithString:[moduleInfo objectForKey:@"name"]];
        _prefix = [[NSString alloc] initWithString:[moduleInfo objectForKey:@"prefix"]];
        _readonly = [[moduleInfo objectForKey:@"readonly"] boolValue];

        NSMutableArray *metrics = [NSMutableArray array];
        for(NSDictionary *metric in [moduleInfo objectForKey:@"metrics"]) {
            SXMetric *sxm = [[SXMetric alloc] initWithName:[metric objectForKey:@"name"] andInfo:[metric objectForKey:@"description"]];
            [metrics addObject:[sxm autorelease]];
        }
        _metrics = [[NSArray alloc] initWithArray:metrics];
        _bundleIdentifier = [[bundle bundleIdentifier] retain];
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *modulesPath = [fm applicationSupportSubDirectory:@"Modules"];
        _tmpPath = [[NSString stringWithFormat:@"%@/%@/tmp", modulesPath, _bundleIdentifier] retain];
        [fm createDirectoryAtPath:_tmpPath withIntermediateDirectories:YES attributes:nil error:nil];
    }
    return self;
}

- (void) analyze:(id)item {

    NSString *theId = [item objectAtIndex:0];
    iSXApp *theItem = [item objectAtIndex:1];
        
    NSMutableDictionary *results = [[NSMutableDictionary alloc] init];
    for(SXMetric *metric in _metrics) {
        [results setObject:[NSNull null] forKey:[NSString stringWithFormat:@"%@_%@", _prefix, metric.name]];
    }

    if ([self itemIsValid:theItem])
    {
        NSString *itemPath = [self temporaryItem:theItem];
        if(itemPath != nil)
        {
            NSInteger pie = 0;
            NSInteger ssp = 0;
            NSInteger arc = 0;
            
            NSString *escAppName = [theItem.name stringByReplacingOccurrencesOfString:@"'"
                                                                      withString:@"'\\''"];
            NSString *decrypted = [NSString stringWithFormat:@"%@/%@/%@.decrypted", itemPath, escAppName, [escAppName stringByDeletingPathExtension]];
            NSArray *args = [NSArray arrayWithObjects: @"-hv", decrypted, nil];
            NSTask *otool = [[NSTask alloc] init];
            NSPipe *output = [NSPipe pipe];
            [otool setStandardOutput:output];
            [otool setLaunchPath:@"/usr/bin/otool"];
            [otool setArguments:args];
            [otool launch];
            
            NSData *dataRead = [[output fileHandleForReading] readDataToEndOfFile];
            NSString *read = [[NSString alloc] initWithData:dataRead encoding:NSUTF8StringEncoding];
            
            if(read != nil)
            {
                if ([read rangeOfString:@"PIE"].location != NSNotFound)
                    pie = 1;
            
                [read release];
            }
            
            [otool waitUntilExit];
            [otool release];
            
            args = [NSArray arrayWithObjects: @"-I", @"-v", decrypted, nil];
            otool = [[NSTask alloc] init];
            output = [NSPipe pipe];
            [otool setStandardOutput:output];
            [otool setLaunchPath:@"/usr/bin/otool"];
            [otool setArguments:args];
            [otool launch];
            
            dataRead = [[output fileHandleForReading] readDataToEndOfFile];
            read = [[NSString alloc] initWithData:dataRead encoding:NSUTF8StringEncoding];
                
            if(read != nil)
            {
                if ([read rangeOfString:@"___stack_chk_fail"].location != NSNotFound && [read rangeOfString:@"___stack_chk_guard"].location != NSNotFound)
                    ssp = 1;
                
                if ([read rangeOfString:@"_objc_release"].location != NSNotFound)
                    arc = 1;
                
                [read release];
            }

            [otool waitUntilExit];
            [otool release];

            
            [results setObject:[NSNumber numberWithInteger:pie]
                        forKey: [NSString stringWithFormat:@"%@_pie", _prefix]];
            [results setObject:[NSNumber numberWithInteger:ssp]
                        forKey: [NSString stringWithFormat:@"%@_ssp", _prefix]];
            [results setObject:[NSNumber numberWithInteger:arc]
                        forKey: [NSString stringWithFormat:@"%@_arc", _prefix]];
            
         //   [self deleteItem:theItem];
        }
    }
    
    [_delegate storeMetrics:[results autorelease] forItem:theId];
}

- (BOOL) itemIsValid:(iSXApp*)item {
    
    if (item.path == nil)
        return NO;
    if (item.ID == nil)
        return NO;
    
    return YES;
}

- (NSString*) temporaryItem:(iSXApp*)item {
    
    NSFileManager *fm = [NSFileManager defaultManager];
    
    if (_readonly)
    {
        @synchronized(self)
        {
            if (![fm fileExistsAtPath:[item.path stringByDeletingPathExtension]])
            {
                NSString *dir = [NSString stringWithFormat:@"--directory=%@", [item.path stringByDeletingLastPathComponent]];
                NSArray *args = [NSArray arrayWithObjects: @"-xf", item.path, dir, nil];
                NSTask *untar = [[NSTask alloc] init];
                [untar setLaunchPath:@"/usr/bin/tar"];
                [untar setArguments:args];
                [untar launch];
                [untar waitUntilExit];
                int exitCode = [untar terminationStatus];
                [untar release];
                
                if (exitCode != 0)
                    return nil;
            }
        }
        return [item.path stringByDeletingLastPathComponent];
    }
    else
    {
        NSString *tmpItemPath = [_tmpPath stringByAppendingPathComponent:item.ID];
        [fm createDirectoryAtPath:tmpItemPath withIntermediateDirectories:YES attributes:nil error:nil];
        
        NSString *dir = [NSString stringWithFormat:@"--directory=%@", tmpItemPath];
        NSArray *args = [NSArray arrayWithObjects: @"-xf", item.path, dir, nil];
        
        NSTask *untar = [[NSTask alloc] init];
        [untar setLaunchPath:@"/usr/bin/tar"];
        [untar setArguments:args];
        [untar launch];
        [untar waitUntilExit];
        int exitCode = [untar terminationStatus];
        [untar release];
        
        return  exitCode == 0 ? [tmpItemPath stringByAppendingPathComponent:item.name] : nil;
    }
}

- (BOOL) deleteItem:(iSXApp*)item {
    
    return [[NSFileManager defaultManager] removeItemAtPath:[_tmpPath stringByAppendingPathComponent:item.ID] error:nil];
}


- (void) dealloc {
    
    [_name release];
    [_prefix release];
    [_metrics release];
    [_bundleIdentifier release];
    [_tmpPath release];
    [super dealloc];
}

@end
