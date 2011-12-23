#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#import <SpringBoard/SBTelephonyManager.h>
#import <Preferences/PSRootController.h>
#import <Preferences/PSDetailController.h>
#import <substrate.h>
#import <Foundation/NSDictionary.h>

#import "KeychainUtils.h"
#import "OAuth/OAConsumer.h"
#import "OAuth/OAMutableURLRequest.h"

#include "Plugin.h"
#import "LinkedInAuthSecrets.h"
#import "JSON/JSONKit.h"

@interface LinkedInAuthController : PSDetailController <UIWebViewDelegate> {
    OAToken *requestToken;
    OAToken *accessToken;

    NSString *apikey;
    NSString *secretkey;
    NSString *requestTokenURLString;
    NSURL *requestTokenURL;
    NSString *accessTokenURLString;
    NSURL *accessTokenURL;
    NSString *userLoginURLString;
    NSURL *userLoginURL;
    NSString *linkedInCallbackURL;
    OAConsumer *consumer;
}

@property(nonatomic, retain) UIWebView *webView;
@property(nonatomic, retain) UIActivityIndicatorView *activity;
@property(nonatomic, retain) OAToken *requestToken;
@property(nonatomic, retain) OAToken *accessToken;

- (void)initAPI;

- (void)requestTokenFromProvider;

- (void)accessTokenFromProvider;

- (OAMutableURLRequest *)makeCallableRequest:(NSString *)urlString format:(NSString *)format;

@end

@implementation LinkedInAuthController

@synthesize webView, activity;
@synthesize requestToken, accessToken;

- (void)initAPI {
    apikey = CONSUMER_KEY;
    secretkey = CONSUMER_SECRET;

    consumer = [[OAConsumer alloc] initWithKey:apikey
                                        secret:secretkey
                                         realm:@"http://api.linkedin.com/"];

    requestTokenURLString = @"https://api.linkedin.com/uas/oauth/requestToken";
    accessTokenURLString = @"https://api.linkedin.com/uas/oauth/accessToken";
    userLoginURLString = @"https://www.linkedin.com/uas/oauth/authorize";
    linkedInCallbackURL = @"hdlinked://linkedin/oauth";

    requestTokenURL = [[NSURL URLWithString:requestTokenURLString] retain];
    accessTokenURL = [[NSURL URLWithString:accessTokenURLString] retain];
    userLoginURL = [[NSURL URLWithString:userLoginURLString] retain];

    NSError *error;
    self.requestToken = [[OAToken alloc] initWithHTTPResponseBody:[KeychainUtils getPasswordForUsername:@"LiRqToken" andServiceName:consumer.realm error:&error]];
    self.accessToken = [[OAToken alloc] initWithHTTPResponseBody:[KeychainUtils getPasswordForUsername:@"LiAcToken" andServiceName:consumer.realm error:&error]];

    if (!self.requestToken || !self.accessToken) {
        NSLog(@"API Failed to init from previously saved.");
    }
}

- (void)dismissView {
    self.webView.delegate = nil;
    [self.webView stopLoading];
    [activity stopAnimating];
    UIApplication *app = [UIApplication sharedApplication];
    app.networkActivityIndicatorVisible = NO;
    if ([self.rootController respondsToSelector:@selector(popControllerWithAnimation:)])
        [self.rootController popControllerWithAnimation:YES];
    else
        [self.rootController popViewControllerAnimated:YES];
}

- (void)requestTokenFromProvider {
    //request token
    OAMutableURLRequest *request =
            [[[OAMutableURLRequest alloc] initWithURL:requestTokenURL
                                             consumer:consumer
                                                token:nil callback:linkedInCallbackURL
                                    signatureProvider:nil] autorelease];
    [request setHTTPMethod:@"POST"];
    NSError *anError = nil;
    [request prepare];
    NSData *data = [NSURLConnection sendSynchronousRequest:request returningResponse:NULL error:&anError];
    //Token received
    if (!anError) {
        NSString *responseBody = [[NSString alloc] initWithData:data
                                                       encoding:NSUTF8StringEncoding];
        self.requestToken = [[[OAToken alloc] initWithHTTPResponseBody:responseBody] autorelease];
        NSError *error;
        [KeychainUtils storeUsername:@"LiRqToken" andPassword:responseBody forServiceName:consumer.realm updateExisting:YES error:&error];
        [responseBody release];

        //Continue with Login
        NSString *userLoginURLWithToken = [NSString stringWithFormat:@"%@?oauth_token=%@&auth_token_secret=%@",
                                                                     userLoginURLString, self.requestToken.key, self.requestToken.secret];
        userLoginURL = [NSURL URLWithString:userLoginURLWithToken];
        NSURLRequest *loginRequest = [NSMutableURLRequest requestWithURL:userLoginURL];
        [webView loadRequest:loginRequest];
    } else {
        //Request token failed
        NSLog(@"Token Request Failed. Error: %@", [anError localizedDescription]);
        [self dismissView];
    }
}

- (BOOL)webView:(UIWebView *)wView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType {
    NSURL *url = request.URL;
    NSString *urlString = url.absoluteString;
    [activity startAnimating];
    BOOL requestForCallbackURL = ([urlString rangeOfString:linkedInCallbackURL].location != NSNotFound);
    if (requestForCallbackURL) {
        BOOL userAllowedAccess = ([urlString rangeOfString:@"user_refused"].location == NSNotFound);
        if (userAllowedAccess) {
            [self.requestToken setVerifierWithUrl:url];
            [self accessTokenFromProvider];
        } else {
            NSLog(@"LI:LinkedIn: Authorization rejected!");
            NSError *error;
            [KeychainUtils deleteItemForUsername:@"LiRqToken" andServiceName:consumer.realm error:&error];
            [KeychainUtils deleteItemForUsername:@"LiAcToken" andServiceName:consumer.realm error:&error];
        }
        [self dismissView];
        return NO;
    }
    return YES; // Case (a) or (b), so ignore it
}

- (void)accessTokenFromProvider {
    OAMutableURLRequest *request =
            [[[OAMutableURLRequest alloc] initWithURL:accessTokenURL
                                             consumer:consumer
                                                token:self.requestToken
                                             callback:nil signatureProvider:nil] autorelease];

    [request setHTTPMethod:@"POST"];
    NSError *anError = nil;
    [request prepare];
    NSData *data = [NSURLConnection sendSynchronousRequest:request returningResponse:NULL error:&anError];
    //Access Token received
    if (data) {
        NSString *responseBody = [[NSString alloc] initWithData:data
                                                       encoding:NSUTF8StringEncoding];
        BOOL problem = ([responseBody rangeOfString:@"oauth_problem"].location != NSNotFound);
        if (problem) {
            NSLog(@"Request access token failed.");
            NSLog(@"%@", responseBody);
        }
        else {
            self.accessToken = [[OAToken alloc] initWithHTTPResponseBody:responseBody];
            NSError *error;
            [KeychainUtils storeUsername:@"LiAcToken" andPassword:responseBody forServiceName:consumer.realm updateExisting:YES error:&error];
        }
        [responseBody release];
    } else {
        NSLog(@"Access token failed. Error: %@", [anError localizedDescription]);
    }
}


- (void)initAuthView {
    self.activity = [[[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhite] autorelease];

    UIView *view = [self view];
    view.autoresizingMask = (UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight);
    view.autoresizesSubviews = YES;

    self.webView = [[[UIWebView alloc] initWithFrame:view.bounds] autorelease];
    self.webView.autoresizesSubviews = YES;
    self.webView.autoresizingMask = (UIViewAutoresizingFlexibleWidth);
    self.webView.scalesPageToFit = YES;
    self.webView.delegate = self;
    [view addSubview:self.webView];
    [self initAPI];

}

- (OAMutableURLRequest *)makeCallableRequest:(NSString *)urlString format:(NSString *)format {
    NSURL *url = [NSURL URLWithString:urlString];
    OAMutableURLRequest *request;
    request = [[[OAMutableURLRequest alloc] initWithURL:url
                                               consumer:consumer
                                                  token:self.accessToken
                                               callback:nil signatureProvider:nil] autorelease];
    [request setValue:format forHTTPHeaderField:@"x-li-format"];
    [request setValue:[NSString stringWithFormat:@"application/%@", format] forHTTPHeaderField:@"Content-Type"];
    return request;

}

- (void)viewWillBecomeVisible:(id)spec {
    [super viewWillBecomeVisible:spec];
    [self initAuthView];
    [self requestTokenFromProvider];
}

- (void)viewWillDisappear:(BOOL)a {
    [super viewWillDisappear:a];
}

- (void)viewWillAppear:(BOOL)a {
    [super viewWillAppear:a];
    [self initAuthView];
    [self.view bringSubviewToFront:self.webView];
    [self requestTokenFromProvider];
}

- (void)setBarButton:(UIBarButtonItem *)button {
    PSRootController *root = self.rootController;
    UINavigationBar *bar = root.navigationBar;
    UINavigationItem *item = bar.topItem;
    item.rightBarButtonItem = button;
}

- (void)webViewDidStartLoad:(UIWebView *)wv {
    CGRect r = self.activity.frame;
    r.size.width += 5;
    UIView *v = [[[UIView alloc] initWithFrame:r] autorelease];
    v.backgroundColor = [UIColor clearColor];
    [v addSubview:self.activity];
    [self.activity startAnimating];
    UIBarButtonItem *button = [[[UIBarButtonItem alloc] initWithCustomView:v] autorelease];
    [self setBarButton:button];

    UIApplication *app = [UIApplication sharedApplication];
    app.networkActivityIndicatorVisible = YES;
}

- (void)webViewDidFinishLoad:(UIWebView *)wv {
    [self.activity stopAnimating];
    [self setBarButton:[[[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:wv action:@selector(reload)] autorelease]];

    UIApplication *app = [UIApplication sharedApplication];
    app.networkActivityIndicatorVisible = NO;
}

- (id)navigationTitle {
    return @"Authentication";
}

- (void)dealloc {
    if (self.webView) {
        self.webView.delegate = nil;
        [self.webView release];
    }
    if (consumer)
        [consumer release];
    if (self.requestToken)
        [self.requestToken release];
    if (self.accessToken)
        [self.accessToken release];
    [super dealloc];
}

@end

#define localize(str) [self.plugin.bundle localizedStringForKey:str value:str table:nil]

#define localizeSpec(str) [self.bundle localizedStringForKey:str value:str table:nil]

#define localizeGlobal(str) [self.plugin.globalBundle localizedStringForKey:str value:str table:nil]

#define UIColorFromRGBA(rgbValue, A) [UIColor colorWithRed:((float)((rgbValue & 0xFF0000) >> 16))/255.0 green:((float)((rgbValue & 0xFF00) >> 8))/255.0 blue:((float)(rgbValue & 0xFF))/255.0 alpha:A]
#define UIColorFromRGB(rgbValue) UIColorFromRGBA(rgbValue, 1.0)

static NSInteger sortByDate(id obj1, id obj2, void *context) {
    double d1 = [[obj1 objectForKey:@"timestamp"] doubleValue];
    double d2 = [[obj2 objectForKey:@"timestamp"] doubleValue];

    if (d1 < d2)
        return NSOrderedDescending;
    else if (d1 > d2)
        return NSOrderedAscending;
    else
        return NSOrderedSame;
}


@interface UpdateSummaryView : UIView

@property(nonatomic, retain) NSString *name;
@property(nonatomic, retain) NSString *update;
@property(nonatomic, retain) NSString *time;
@property(nonatomic, retain) UIImage *image;
@property(nonatomic, retain) LITheme *theme;

@end

@implementation UpdateSummaryView

@synthesize name, time, image, theme, update;

- (void)setFrame:(CGRect)r {
    [super setFrame:r];
    [self setNeedsDisplay];
}

- (void)drawRect:(CGRect)rect {
    CGRect r = self.superview.bounds;

    NSString *theName = self.name;
    CGSize nameSize = [theName sizeWithFont:self.theme.summaryStyle.font constrainedToSize:CGSizeMake(r.size.width - 80, self.theme.summaryStyle.font.leading) lineBreakMode:UILineBreakModeTailTruncation];

    [theName drawInRect:CGRectMake(45, 3, nameSize.width, nameSize.height) withLIStyle:self.theme.summaryStyle lineBreakMode:UILineBreakModeTailTruncation];
    LIStyle *timeStyle = [self.theme.detailStyle copy];
    timeStyle.font = [UIFont systemFontOfSize:self.theme.detailStyle.font.pointSize];
    CGSize timeSize = [self.time sizeWithFont:timeStyle.font];
    [self.time drawInRect:CGRectMake(r.size.width - timeSize.width - 5, nameSize.height - timeSize.height, timeSize.width, timeSize.height) withLIStyle:timeStyle lineBreakMode:UILineBreakModeClip alignment:UITextAlignmentRight];
    [timeStyle release];

    CGSize s = [self.update sizeWithFont:self.theme.detailStyle.font constrainedToSize:CGSizeMake(r.size.width - 60, self.theme.detailStyle.font.leading * 2) lineBreakMode:UILineBreakModeTailTruncation];
    [self.update drawInRect:CGRectMake(45, nameSize.height + 3, s.width, s.height) withLIStyle:self.theme.detailStyle lineBreakMode:UILineBreakModeTailTruncation];
    CGRect imageRect = CGRectMake(5, 7, 30, 30);
    [self.image drawInRoundedRect:imageRect withRadius:1];

}

- (void)dealloc {
    [name release];
    [time release];
    [image release];
    [theme release];
    [update release];
    [super dealloc];
}

@end

@interface ProfileHeadingView : UIView

@property(nonatomic, retain) NSString *name;
@property(nonatomic, retain) NSString *headline;
@property(nonatomic, retain) UIImage *image;
@property(nonatomic, retain) UIColor *headlineColor;
@property(nonatomic, retain) UIColor *nameColor;
@property(nonatomic, retain) UIColor *shadowColor;

- (ProfileHeadingView *)initWithName:(NSString *)name headline:(NSString *)headline image:(UIImage *)image;

@end

@implementation ProfileHeadingView

@synthesize name, image, headline, nameColor, headlineColor, shadowColor;

- (ProfileHeadingView *)initWithName:(NSString *)name headline:(NSString *)headline image:(UIImage *)image; {
    self = [super init];
    self.name = name;
    self.headline = headline;
    self.image = image;
    nameColor = [UIColor blackColor];
    headlineColor = [UIColor blackColor];
    shadowColor = [UIColor whiteColor];
    return self;
}

- (void)setFrame:(CGRect)r {
    [super setFrame:r];
    [self setNeedsDisplay];
}

- (void)drawRect:(CGRect)rect {
    CGRect r = self.superview.bounds;


    if (self.image) {
        CGRect imageRect = CGRectMake(10, 15, 55, 55);
        [self.image drawInRoundedRect:imageRect withRadius:5 border:YES];
    }

    CGContextRef context = UIGraphicsGetCurrentContext();
    CGContextSaveGState(context);

    CGContextSetShadowWithColor(context, CGSizeMake(0.0f, 2.0f), 0.0f, [shadowColor CGColor]);

    CGContextSetFillColorWithColor(context, [nameColor CGColor]);
    NSString *theName = self.name;
    UIFont *font = [UIFont boldSystemFontOfSize:18];
    CGSize nameSize = [theName sizeWithFont:font constrainedToSize:CGSizeMake(r.size.width - 85, font.leading) lineBreakMode:UILineBreakModeTailTruncation];
    [theName drawInRect:CGRectMake(75, 15, nameSize.width, nameSize.height) withFont:font lineBreakMode:UILineBreakModeTailTruncation];

    CGContextSetFillColorWithColor(context, [headlineColor CGColor]);
    UIFont *headlineFont = [UIFont systemFontOfSize:14];
    CGSize s = [self.headline sizeWithFont:headlineFont constrainedToSize:CGSizeMake(r.size.width - 85, headlineFont.leading * 2) lineBreakMode:UILineBreakModeTailTruncation];
    [self.headline drawInRect:CGRectMake(75, nameSize.height + 12, s.width, s.height) withFont:headlineFont lineBreakMode:UILineBreakModeTailTruncation];

}

- (void)dealloc {
    [name release];
    [image release];
    [headline release];
    [super dealloc];
}

@end

//Categories

@interface UIWebView (WebViewBounce)
- (void)setBounce:(BOOL)bounce;
@end

@implementation UIWebView (WebViewBounce)

- (void)setBounce:(BOOL)bounce {
    if (!bounce) {
        for (id subview in self.subviews)
            if ([[subview class] isSubclassOfClass:[UIScrollView class]])
                ((UIScrollView *) subview).bounces = NO;
    }
}

@end

@interface UIKeyboardImpl : UIView
@property(nonatomic, retain) id delegate;
@end

@interface UIKeyboard : UIView

+ (UIKeyboard *)activeKeyboard;

+ (void)initImplementationNow;

+ (CGSize)defaultSize;

@end


static int tapCount = 0;
static NSTimeInterval lastFetchTime = 0;
static NSString *const NO_IMG_URL = @"http://static01.linkedin.com/scds/common/u/img/icon/icon_no_photo_no_border_60x60.png";
static NSString *const UPDATE_WEB_URL_FORMAT = @"https://touch.www.linkedin.com/#nusdetail/%@";

@interface LinkedInPlugin : UIViewController <LIPluginController, LITableViewDelegate, UITableViewDataSource, LIPreviewDelegate, UIWebViewDelegate, UIActionSheetDelegate> {
    NSTimeInterval nextUpdate;
    NSConditionLock *lock;
}

@property(nonatomic, retain) LIPlugin *plugin;
//@property(retain) NSMutableArray *updates;
@property(retain) NSMutableArray *activeUpdates;
@property(retain) NSMutableDictionary *imageCache;
@property(nonatomic, retain) UINavigationController *previewController;

@property(retain) NSMutableDictionary *networkStream;

// preview stuff
@property(nonatomic, retain) NSMutableDictionary *selectedUpdate;
@property(nonatomic, retain) UIWebView *summaryWebView;

@property(nonatomic, retain) UIActionSheet *actionSheet;
@property(nonatomic, retain) UIView *readView;
@property(nonatomic, retain) UIView *writeView;
@property(nonatomic, retain) UITextView *textView;
@property(nonatomic, retain) UIActivityIndicatorView *activity;
//@property(nonatomic, retain) UITableView *tableView;
@property(nonatomic, retain) LinkedInAuthController *authController;

- (UIView *)showEditView;

@end

@implementation LinkedInPlugin

@synthesize networkStream, activeUpdates, plugin, imageCache, previewController, authController;

@synthesize selectedUpdate, summaryWebView, readView, activity, writeView, textView, actionSheet;

- (NSString *)timeToString:(NSNumber *)dateNum {
    NSString *timeString = @"";
    if (dateNum == nil) return timeString;
    int diff = 0 - (int) [[NSDate dateWithTimeIntervalSince1970:dateNum.longValue] timeIntervalSinceNow];
    if (diff > 86400) {
        int n = (diff / 86400);
        timeString = [NSString stringWithFormat:localize(@"%dd ago"), n];
    }
    else if (diff > 3600) {
        int n = (diff / 3600);
        if (diff % 3600 > 1800)
            n++;

        timeString = [NSString stringWithFormat:localize(@"about %dh ago"), n];
    }
    else if (diff > 60) {
        int n = (diff / 60);
        if (diff % 60 > 30)
            n++;

        timeString = [NSString stringWithFormat:localize(@"%dm ago"), n];
    }
    else {
        timeString = [NSString stringWithFormat:localize(@"%ds ago"), diff];
    }

    return timeString;

}

- (void)updateCommentsAndLikes {
    UILabel *cmtsLbl = (UILabel *) [self.readView viewWithTag:103];

    int numLikes = [[self.selectedUpdate objectForKey:@"numLikes"] intValue];

    id total = [self.selectedUpdate valueForKeyPath:@"updateComments.values"];

    int numComments = total ? [total count] : 0;

    NSMutableArray *labelTexts = [NSMutableArray arrayWithCapacity:2];

    if (numComments > 1) {
        [labelTexts addObject:[NSString stringWithFormat:@"%d Comments", numComments]];
    } else if (numComments > 0) { //1
        [labelTexts addObject:@"1 Comment"];
    }

    if (numLikes > 1) {
        [labelTexts addObject:[NSString stringWithFormat:@"%d Likes", numLikes]];
    } else if (numLikes > 0) { //1
        [labelTexts addObject:@"1 Like"];
    }

    if ([labelTexts count] > 0) {
        cmtsLbl.text = [labelTexts componentsJoinedByString:@" and "];
        cmtsLbl.hidden = NO;
    } else {
        cmtsLbl.hidden = YES;
    }

}

- (void)adjustScrollViewHeight {
    UIScrollView *scrollView = (UIScrollView *) [self.readView viewWithTag:101];
    float contentHeight = 0;
    UIView *previousView = nil;
    for (UIView *aView in scrollView.subviews) {
        if ((aView.tag > 101 && aView.tag < 105) || aView.tag >= 200 && !aView.hidden) {
            contentHeight += aView.frame.size.height + 15;
            if (previousView) {
                aView.frame = CGRectMake(aView.frame.origin.x, 15 + previousView.frame.origin.y + previousView.frame.size.height,
                        aView.frame.size.width, aView.frame.size.height);
            }
            previousView = aView;
        }
    }
    scrollView.contentSize = CGSizeMake(scrollView.frame.size.width, contentHeight + 40);
}

- (void)fillDetailView:(NSMutableDictionary *)update {
    if (NSString *name = [update objectForKey:@"name"]) {

        NSString *imageUrl = [update objectForKey:@"pictureUrl"];

        ProfileHeadingView *headingView = (ProfileHeadingView *) [self.readView viewWithTag:100]; //Profile Heading view

        headingView.name = name;
        headingView.image = [self.imageCache objectForKey:imageUrl];
        headingView.headline = [update valueForKeyPath:@"headline"];
        [headingView setNeedsDisplay];


        NSString *updateText = [update objectForKey:@"update"];
        NSString *date = [update objectForKey:@"time"];
        NSString *html = [NSString stringWithFormat:@"<html><head><style>div{padding:10px;}#time{font-size:small;color:gray;}a{text-decoration:none;color:#3579db;font-weight:bold;}body{font:18px 'Helvetica Neue',Helvetica,sans-serif;background:#D9D6CF;}</style></head><body><div id='update'>%@</div><div id='time'>%@</div></body></html>",
                                                    updateText, date];
        [self.summaryWebView loadHTMLString:html baseURL:[NSURL URLWithString:@""]];
        [self updateCommentsAndLikes];
    }
}

- (void)showKeyboard:(UIView *)tView {
    if ([self.plugin respondsToSelector:@selector(showKeyboard:)]) {
        [self.plugin showKeyboard:tView];
    }
    else {
        if (Class peripheral = objc_getClass("UIPeripheralHost")) {
            [[peripheral sharedInstance] setAutomaticAppearanceEnabled:YES];
            [[peripheral sharedInstance] orderInAutomatic];
        }
        else {
            [[UIKeyboard automaticKeyboard] orderInWithAnimation:YES];
        }
    }
}

- (void)hideKeyboard {
    if ([self.plugin respondsToSelector:@selector(hideKeyboard)]) {
        [self.plugin hideKeyboard];
    }
    else {
        if (Class peripheral = objc_getClass("UIPeripheralHost")) {
            [[peripheral sharedInstance] orderOutAutomatic];
            [[peripheral sharedInstance] setAutomaticAppearanceEnabled:NO];
        }
        else {
            [[UIKeyboard automaticKeyboard] orderOutWithAnimation:YES];
        }
    }
}

- (void)loadView {

    UIView *v = [[[UIView alloc] initWithFrame:[[UIScreen mainScreen] applicationFrame]] autorelease];
    self.view = v;
    v.backgroundColor = [UIColor blackColor];

    UIView *rView = [[[UIView alloc] initWithFrame:v.bounds] autorelease];
    self.readView = rView;
    rView.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    rView.backgroundColor = UIColorFromRGB(0xD9D6CF);

    UIView *header = [[[UIView alloc] initWithFrame:CGRectMake(-1, -1, v.frame.size.width + 2, 85)] autorelease];
    header.autoresizingMask = UIViewAutoresizingFlexibleWidth;

    ProfileHeadingView *headingView = [[[ProfileHeadingView alloc] initWithName:@"" headline:@"" image:nil] autorelease];
    headingView.nameColor = [UIColor whiteColor];
    headingView.headlineColor = UIColorFromRGB(0x88BCD1);
    headingView.shadowColor = [UIColor clearColor];
    headingView.frame = header.frame;
    headingView.tag = 100;
    [headingView sizeToFit];
    headingView.backgroundColor = [UIColor clearColor];
    headingView.autoresizingMask = UIViewAutoresizingFlexibleWidth;

    CAGradientLayer *gradient = [CAGradientLayer layer];
    gradient.frame = header.bounds;
    gradient.colors = [NSArray arrayWithObjects:(id) [UIColorFromRGB(0x1f6a8d) CGColor], (id) [UIColorFromRGB(0x0e3e54) CGColor], nil];
    [header.layer insertSublayer:gradient atIndex:0];

    header.layer.borderWidth = 1.0;
    header.layer.borderColor = [UIColorFromRGB(0x333333) CGColor];//[UIColorFromRGB(0x1f6a8d) CGColor];
    header.clipsToBounds = NO;
    header.layer.shadowOffset = CGSizeMake(0, 1.0);
    header.layer.shadowOpacity = 1.0 ;
    header.layer.shadowRadius  = 2.0;
    header.layer.shadowColor  = [UIColorFromRGB(0x333333) CGColor];

    [header addSubview:headingView];

    [rView addSubview:header];

    UIScrollView *scrollView = [[[UIScrollView alloc] initWithFrame:CGRectMake(-1, 86, v.frame.size.width + 2, v.frame.size.height - 135)] autorelease];
    scrollView.tag = 101;
    scrollView.bounces = YES;
    scrollView.alwaysBounceVertical = YES;


    UIWebView *summaryView = [[[UIWebView alloc] initWithFrame:CGRectMake(-1, 0, v.frame.size.width + 1, 100)] autorelease];
    self.summaryWebView = summaryView;
    summaryView.tag = 102;
    summaryView.delegate = self;
    summaryView.dataDetectorTypes = (UIDataDetectorTypeLink | UIDataDetectorTypePhoneNumber);
    summaryView.backgroundColor = [UIColor clearColor];
    summaryView.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [summaryView setBounce:NO];
    [scrollView addSubview:summaryView];


    //    [rView addSubview:summaryView];

    UILabel *commentsLbl = [[[UILabel alloc] initWithFrame:CGRectMake(15, summaryView.frame.size.height, v.frame.size.width - 30, 40)] autorelease];
    commentsLbl.tag = 103;
    commentsLbl.textColor = [UIColor whiteColor];
    commentsLbl.text = @"Comments and Likes";
    commentsLbl .textAlignment = UITextAlignmentCenter;
    commentsLbl.backgroundColor = UIColorFromRGB(0x888888);
    commentsLbl.hidden = YES;
    commentsLbl.userInteractionEnabled = YES;
    UITapGestureRecognizer *tapGesture =
            [[[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(doOpen)] autorelease];
    [commentsLbl addGestureRecognizer:tapGesture];

    commentsLbl.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleTopMargin;
    commentsLbl.layer.borderWidth = 2.0;
    commentsLbl.layer.borderColor = [UIColorFromRGB(0x666666) CGColor];
    commentsLbl.layer.cornerRadius = 15.0;


    [scrollView addSubview:commentsLbl];

    self.activity = [[[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray] autorelease];
    self.activity.hidesWhenStopped = YES;

    self.activity.center = CGPointMake(scrollView.frame.size.width / 2, scrollView.frame.size.height / 2);

    [scrollView addSubview:self.activity];

    [rView insertSubview:scrollView belowSubview:header];

    [v addSubview:rView];

    UIView *wView = [[[UIView alloc] initWithFrame:v.bounds] autorelease];
    self.writeView = wView;
    wView.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    wView.backgroundColor = UIColorFromRGB(0xD9D6CF);

    UITextView *tv = [[[UITextView alloc] initWithFrame:CGRectMake(5, 7, wView.frame.size.width - 10, [UIKeyboard defaultSize].height - 30)] autorelease];
    self.textView = tv;

    tv.backgroundColor = [UIColor whiteColor];
    tv.editable = YES;
    tv.userInteractionEnabled = YES;
    tv.keyboardAppearance = UIKeyboardAppearanceAlert;
    tv.font = [UIFont systemFontOfSize:20];
    tv.textColor = [UIColor blackColor];
    tv.layer.cornerRadius = 5;
    tv.layer.borderWidth = 2.0;
    tv.layer.borderColor = [UIColorFromRGB(0x1f6a8d) CGColor];

    [wView addSubview:textView];
    [v addSubview:writeView];

    self.actionSheet = [[[UIActionSheet alloc] initWithTitle:@"Launch LinkedIn" delegate:self cancelButtonTitle:@"Cancel" destructiveButtonTitle:nil otherButtonTitles:@"Native Application", @"In Safari", nil] autorelease];

    if ([self.selectedUpdate objectForKey:@"name"]) {
        [self fillDetailView:self.selectedUpdate];
    }
}

- (void)actionSheet:(UIActionSheet *)actSheet clickedButtonAtIndex:(NSInteger)buttonIndex {

    if (buttonIndex == 0) {   //open app - unfortunately linkedin has no URL scheme to open this update directly.
        [self.plugin launchApplicationWithIdentifier:@"com.linkedin.LinkedIn"];
    } else if (buttonIndex == 1) { //open safari
        NSString *urlString = [NSString stringWithFormat:UPDATE_WEB_URL_FORMAT, [self.selectedUpdate objectForKey:@"updateKey"]];
        [self.plugin launchURL:[NSURL URLWithString:urlString]];
    }

}

- (void)dismissDetailView {
    [self.plugin dismissPreview];
}

- (void)previewWillShow:(LIPreview *)preview {
    [preview setNeedsLayout];
}

- (void)previewWillDismiss:(LIPreview *)preview {
    if ([self.actionSheet isVisible]) {
        [self.actionSheet dismissWithClickedButtonIndex:self.actionSheet.cancelButtonIndex animated:YES];
        return;
    }
    [self.textView resignFirstResponder];
    [self hideKeyboard];
}

- (void)hideConnViews {
    UIScrollView *scrollView = (UIScrollView *) [self.readView viewWithTag:101];
    for (UIView *aView in scrollView.subviews) {
        if (aView.tag >= 200) {
            aView.hidden = YES;
        }
    }
}

- (void)previewDidDismiss:(LIPreview *)preview {

    [self hideConnViews];

}

- (void)like {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    [self.authController initAPI];
    if (!self.authController.accessToken || !self.authController.accessToken.key || !self.authController.accessToken.secret) {
        NSLog(@"LI: LinkedIn: No authorization!");
        return;
    }
    NSString *likeUrl = [NSString stringWithFormat:@"https://api.linkedin.com/v1/people/~/network/updates/key=%@/is-liked", [[self.selectedUpdate objectForKey:@"updateKey"] encodedURLParameterString]];
    OAMutableURLRequest *request = [self.authController makeCallableRequest:likeUrl format:@"xml"];
    [request setHTTPMethod :@"PUT"];
    [request prepare];

    BOOL isLiked = ![[self.selectedUpdate objectForKey:@"isLiked"] boolValue];
    NSString *body = [NSString stringWithFormat:@"<?xml version='1.0' encoding='UTF-8'?><is-liked>%@</is-liked>", isLiked ? @"true" : @"false"];
    [request setHTTPBody :[body dataUsingEncoding:NSUTF8StringEncoding]];
    NSError *anError = nil;
    NSData *data = [NSURLConnection sendSynchronousRequest:request returningResponse:NULL error:&anError];
    [activity stopAnimating];
    UIBarButtonItem *likeBtn = [self.toolbarItems objectAtIndex:0];
    if (data == nil || anError != nil) {
        NSLog(@"LI:LinkedIn: Like operation Failed. %@", anError);
        if (likeBtn) {
            likeBtn.enabled = YES;
        }
    } else {
        [self.selectedUpdate setObject:isLiked ? @"true" : @"false" forKey:@"isLiked"];
        int numLikes = [[self.selectedUpdate objectForKey:@"numLikes"] intValue];
        [self.selectedUpdate setObject:[NSNumber numberWithInt:numLikes + (isLiked ? 1 : -1)] forKey:@"numLikes"];
        if (likeBtn) {
            UIImage *img = [UIImage li_imageWithContentsOfResolutionIndependentFile:[self.plugin.bundle pathForResource:!isLiked ? @"Like" : @"Unlike" ofType:@"png"]];
            likeBtn.image = img;

        }
    }
    if (likeBtn) {
        likeBtn.enabled = YES;
    }
    [self updateCommentsAndLikes];
    [pool release];
}

- (void)comment:(NSString *)text {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    [self.authController initAPI];
    if (!self.authController.accessToken || !self.authController.accessToken.key || !self.authController.accessToken.secret) {
        NSLog(@"LI: LinkedIn: No authorization!");
        return;
    }
    NSString *likeUrl = [NSString stringWithFormat:@"https://api.linkedin.com/v1/people/~/network/updates/key=%@/update-comments", [[self.selectedUpdate objectForKey:@"updateKey"] encodedURLParameterString]];
    OAMutableURLRequest *request = [self.authController makeCallableRequest:likeUrl format:@"xml"];
    [request setHTTPMethod :@"POST"];

    [request prepare];
    NSString *body = [NSString stringWithFormat:@"<?xml version='1.0' encoding='UTF-8'?><update-comment><comment>%@</comment></update-comment>", text];
    [request setHTTPBodyWithString:body];
    NSError *anError = nil;
    NSURLResponse *response;
    NSData *data = [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:&anError];
    if (data == nil || anError != nil) {
        NSLog(@"LI:LinkedIn: Comment operation Failed. %@", anError);
    } else {
        NSLog(@"LI:LinkedIn: Comment posted successfully.");
    }
    [pool release];
}

- (void)doLike {
    UIBarButtonItem *likeBtn = [self.toolbarItems objectAtIndex:0];
    if (likeBtn) {
        likeBtn.enabled = NO;
        [activity startAnimating];
    }
    [self performSelectorInBackground:@selector(like) withObject:nil];
}

- (void)doOpen {
    UIBarButtonItem *openBtn = [self.toolbarItems lastObject];
    if (openBtn) {
        [self.actionSheet showFromBarButtonItem:openBtn animated:YES];
    }

}

- (void)postComment {
    [self performSelectorInBackground:@selector(comment:) withObject:self.textView.text];
    [self.plugin dismissPreview];
}

- (void)doComment {
    self.navigationItem.title = localize(@"Comment");

    [self showEditView];
}

- (UIView *)showEditView {

    [self.textView setText:@""];
    [self.writeView setFrame:CGRectMake(0.0f, self.writeView.frame.size.height, self.writeView.frame.size.width, self.writeView.frame.size.height)];
    [self.view sendSubviewToBack:self.readView];
    [self.view bringSubviewToFront:self.writeView];

    [UIView beginAnimations:@"switchToEdit" context:nil];
    [UIView setAnimationDuration:.3];
    [self.writeView setFrame:CGRectMake(0.0f, 0.0f, self.writeView.frame.size.width, self.writeView.frame.size.height)];
    [UIView commitAnimations];

    self.navigationItem.rightBarButtonItem = [[[UIBarButtonItem alloc] initWithTitle:localizeGlobal(@"Send") style:UIBarButtonItemStyleDone target:self action:@selector(postComment)] autorelease];

    [self.textView becomeFirstResponder];
    [self showKeyboard:self.textView];

    return self.previewController.view;
}

- (UIView *)showDetailView:(NSMutableDictionary *)update {
    [self.view sendSubviewToBack:self.writeView];
    [self.view bringSubviewToFront:self.readView];

    self.navigationItem.title = localize(@"LinkedIn");
    self.navigationItem.leftBarButtonItem = [[[UIBarButtonItem alloc] initWithTitle:localizeGlobal(@"Cancel") style:UIBarButtonItemStyleBordered target:self action:@selector(dismissDetailView)] autorelease];
    self.navigationItem.rightBarButtonItem = nil;

    self.selectedUpdate = update;

    if (self.isViewLoaded) {
        [self fillDetailView:self.selectedUpdate];
    }
    self.previewController = [[[UINavigationController alloc] initWithRootViewController:self] autorelease];
    UINavigationBar *bar = self.previewController.navigationBar;
    bar.barStyle = UIBarStyleBlackOpaque;

    UIToolbar *toolbar = [self.previewController toolbar];
    toolbar.barStyle = UIBarStyleBlackOpaque;


    NSMutableArray *buttons = [NSMutableArray array];
    UIBarButtonItem *flexspace = [[[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemFlexibleSpace target:nil action:nil] autorelease];


    BOOL isLikable = [[self.selectedUpdate objectForKey:@"isLikable"] boolValue];
    BOOL isLiked = [[self.selectedUpdate objectForKey:@"isLiked"] boolValue];
    if (isLikable) {

        UIImage *img = [UIImage li_imageWithContentsOfResolutionIndependentFile:[self.plugin.bundle pathForResource:isLiked ? @"Unlike" : @"Like" ofType:@"png"]];

        UIBarButtonItem *likeBtn = [[[UIBarButtonItem alloc] initWithImage:img style:UIBarButtonItemStylePlain target:self action:@selector(doLike)] autorelease];
        [buttons addObject:likeBtn];
        [buttons addObject:flexspace];
    }

    BOOL isCommentable = [[self.selectedUpdate objectForKey:@"isCommentable"] boolValue];
    if (isCommentable) {

        UIImage *img = [UIImage li_imageWithContentsOfResolutionIndependentFile:[self.plugin.bundle pathForResource:@"Comment" ofType:@"png"]];

        UIBarButtonItem *commentBtn = [[[UIBarButtonItem alloc] initWithImage:img style:UIBarButtonItemStylePlain target:self action:@selector(doComment)] autorelease];
        [buttons addObject:commentBtn];
        [buttons addObject:flexspace];
    }

    UIImage *img = [UIImage li_imageWithContentsOfResolutionIndependentFile:[self.plugin.bundle pathForResource:@"Open" ofType:@"png"]];

    UIBarButtonItem *openBtn = [[[UIBarButtonItem alloc] initWithImage:img style:UIBarButtonItemStylePlain target:self action:@selector(doOpen)] autorelease];
    [buttons addObject:openBtn];

    [self.previewController setToolbarHidden:NO];
    [self setToolbarItems:buttons];

    return self.previewController.view;
}

- (void)resetTapCount {
    tapCount = 0;
}

- (void)refreshUpdatesInView {
    [self.plugin updateView:[NSDictionary dictionaryWithObjectsAndKeys:self.activeUpdates, @"updates", nil]];
}

static void callInterruptedApp(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    NSLog(@"LI:LinkedIn: Call interrupted app");
}

static void activeCallStateChanged(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    NSLog(@"LI:LinkedIn: Call state changed");
}

- (id)initWithPlugin:(LIPlugin *)thePlugin {
    self = [super init];
    self.plugin = thePlugin;
    self.imageCache = [NSMutableDictionary dictionaryWithCapacity:10];

    self.activeUpdates = [NSMutableArray arrayWithCapacity:10];

    self.authController = [LinkedInAuthController alloc];
    [self.authController initAPI];

    lock = [[NSConditionLock alloc] init];

    thePlugin.tableViewDataSource = self;
    thePlugin.tableViewDelegate = self;
    thePlugin.previewDelegate = self;

    NSNotificationCenter *center = [NSNotificationCenter defaultCenter];
    [center addObserver:self selector:@selector(update:) name:LITimerNotification object:nil];
    [center addObserver:self selector:@selector(update:) name:LIViewReadyNotification object:nil];

    return self;
}

- (void)dealloc {
    [lock release];
    [networkStream release];
    [selectedUpdate release];
    [activeUpdates release];
    [plugin release];
    [imageCache release];
    [previewController release];
    [summaryWebView release];
    [readView release];
    [activity release];
    [authController release];
    [writeView release];
    [textView release];
    [actionSheet release];
    [super dealloc];
}

- (BOOL)loadUpdates:(NSString *)url parameters:(NSDictionary *)parameters {
    NSString *fullURL = url;
    if (parameters.count > 0) {
        NSMutableArray *paramArray = [NSMutableArray arrayWithCapacity:parameters.count];
        for (id key in parameters)
            [paramArray addObject:[NSString stringWithFormat:@"%@=%@", key, [parameters objectForKey:key]]];

        fullURL = [fullURL stringByAppendingFormat:@"?%@", [paramArray componentsJoinedByString:@"&"]];
    }
    [self.authController initAPI];
    if (!self.authController.accessToken || !self.authController.accessToken.key || !self.authController.accessToken.secret) {
        NSLog(@"No authorization!");
        return NO;
    }

    OAMutableURLRequest *request = [self.authController makeCallableRequest:fullURL format:@"json"];
    [request prepare];

    NSError *anError = nil;
    NSData *data = [NSURLConnection sendSynchronousRequest:request returningResponse:NULL error:&anError];

    if (data == nil) {
        NSLog(@"LI:LinkedIn: NO DATA: %@", anError);
        return NO;
    }

    self.networkStream = [data mutableObjectFromJSONData];
    if (self.networkStream == nil || [[self.networkStream objectForKey:@"values"] count] <= 0) {
        NSLog(@"LI:LinkedIn: Not enough updateds returned since last fetch (%f). %@", lastFetchTime, [anError localizedDescription]);
        NSLog(@"LI:LinkedIn: RESPONSE: %@", [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease]);
        return NO;
    }
    return YES;
}

- (void)prepareUpdateForUse:(NSMutableDictionary *)elem {
    if ([elem objectForKey:@"prepared"]) return;

    @synchronized (elem) {
        NSString *value = [elem objectForKey:@"name"];
        if (!value) {
            value = [NSString stringWithFormat:@"%@ %@", [elem valueForKeyPath:@"updateContent.person.firstName"], [elem valueForKeyPath:@"updateContent.person.lastName"]];
            [elem setObject:[[value copy] autorelease] forKey:@"name"];
        }

        value = [elem objectForKey:@"headline"];
        if (!value) {
            value = [elem valueForKeyPath:@"updateContent.person.headline"];
            if (value)
                [elem setObject:value forKey:@"headline"];
        }

        value = [elem valueForKeyPath:@"pictureUrl"];
        if (!value) {
            value = [elem valueForKeyPath:@"updateContent.person.pictureUrl"];
            if (!value) {
                value = NO_IMG_URL;
            }
            [elem setValue:[[value copy] autorelease] forKeyPath:@"pictureUrl"];
        }
        UIImage *image = [self.imageCache objectForKey:value];
        if (!image) {
            image = [UIImage imageWithData:[NSData dataWithContentsOfURL:[NSURL URLWithString:[[value copy] autorelease]]]];
            [self.imageCache setValue:image forKey:value];
        }
        NSString *updateType = [elem objectForKey:@"updateType"];
        if ([updateType isEqualToString:@"CONN"]) {                         //CONN
            value = [elem objectForKey:@"update"];
            if (!value) {
                NSArray *connections = [elem valueForKeyPath:@"updateContent.person.connections.values"];
                value = [NSString stringWithFormat:@"%@ is now connected to", [elem objectForKey:@"name"]];
                for (int i = 0, length = connections ? [connections count] : 0; i < length; i++) {
                    NSDictionary *connection = [connections objectAtIndex:i];
                    NSString *connectionName = [NSString stringWithFormat:@"%@ %@ (%@)", [connection objectForKey:@"firstName"], [connection objectForKey:@"lastName"], [connection objectForKey:@"headline"]];
                    value = [value stringByAppendingFormat:@" %@%@", (i < length - 2 ? @", " : (i == length - 2 ? @"and " : @"")), connectionName];
                }
                [elem setObject:value forKey:@"update"];
            }
        } else if ([updateType isEqualToString:@"STAT"]) {                  //STAT
            value = [elem objectForKey:@"update"];
            if (!value) {
                value = [elem valueForKeyPath:@"updateContent.person.currentStatus"];
                [elem setObject:value forKey:@"update"];
            }
        } else if ([updateType isEqualToString:@"MSFC"]) { //Member started following company    //MSFC
            value = [NSString stringWithFormat:@"%@ %@", [elem valueForKeyPath:@"updateContent.companyPersonUpdate.person.firstName"], [elem valueForKeyPath:@"updateContent.companyPersonUpdate.person.lastName"]];
            [elem setObject:[[value copy] autorelease] forKey:@"name"];

            [elem setObject:[elem valueForKeyPath:@"updateContent.companyPersonUpdate.person.headline"] forKey:@"headline"];

            value = [elem valueForKeyPath:@"updateContent.companyPersonUpdate.person.pictureUrl"];
            if (!value) {
                value = [elem objectForKey:@"pictureUrl"];
            }
            image = [self.imageCache objectForKey:value];
            if (!image) {
                image = [UIImage imageWithData:[NSData dataWithContentsOfURL:[NSURL URLWithString:[[value copy] autorelease]]]];
                [self.imageCache setValue:image forKey:value];
            }
            value = [elem objectForKey:@"update"];
            if (!value) {
                value = [elem valueForKeyPath:@"updateContent.company.name"];
                value = [NSString stringWithFormat:@"%@ started following %@", [elem objectForKey:@"name"], value];
                [elem setObject:value forKey:@"update"];
            }
        } else if ([updateType isEqualToString:@"JGRP"]) {//member joined a group               JGRP
            value = [elem objectForKey:@"update"];
            if (!value) {
                NSArray *groups = [elem valueForKeyPath:@"updateContent.person.memberGroups.values"];
                value = [NSString stringWithFormat:@"%@ has joined group%@", [elem objectForKey:@"name"], (groups && [groups count] > 1) ? @"s" : @""];//person name
                for (int i = 0, length = groups ? [groups count] : 0; i < length; i++) {
                    NSString *groupName = [[groups objectAtIndex:i] objectForKey:@"name"];
                    value = [value stringByAppendingFormat:@" %@%@", (i < length - 2 ? @", " : (i == length - 2 ? @"and " : @"")), groupName];
                }
                [elem setObject:value forKey:@"update"];
            }
        } else if ([updateType isEqualToString:@"APPM"] || [updateType isEqualToString:@"APPS"]) {          //APPM APPS
            value = [elem objectForKey:@"update"];
            if (!value) {
                NSArray *activities = [elem valueForKeyPath:@"updateContent.person.personActivities.values"];
                value = @"";
                for (int i = 0, length = activities ? [activities count] : 0; i < length; i++) {
                    NSString *groupName = [[activities objectAtIndex:i] objectForKey:@"body"];
                    value = [value stringByAppendingFormat:@" %@%@", (i < length - 2 ? @", " : (i == length - 2 ? @"and " : @"")), groupName];
                }
            }
            [elem setObject:value forKey:@"update"];
        } else if ([updateType isEqualToString:@"PROF"]) {                          //PROF
            value = [elem objectForKey:@"update"];
            if (!value) {
//                NSArray *positions = [elem valueForKeyPath:@"updateContent.person.positions.values"];
                value = [NSString stringWithFormat:@"%@ has updated profile.", [elem objectForKey:@"name"]];
                /*for (int i = 0, length = positions ? [positions count] : 0; i < length; i++) {
                    NSDictionary *position = [positions objectAtIndex:i];
                    NSString *positionName = [position objectForKey:@"title"];
                    NSString *companyName = [[position objectForKey:@"company"] objectForKey:@"name"];
                    value = [value stringByAppendingFormat:@" %@%@ at %@", (i < length - 2 ? @", " : (i == length - 2 ? @"and " : @"")), positionName, companyName];
                }*/
            }
            [elem setObject:value forKey:@"update"];
        } else if ([updateType isEqualToString:@"PROF"]) {                          //PICU
            value = [elem objectForKey:@"update"];
            if (!value) {
                value = [NSString stringWithFormat:@"%@ has updated profile photo.", [elem objectForKey:@"name"]];
            }
            [elem setObject:value forKey:@"update"];
        } else if ([updateType isEqualToString:@"NCON"]) {                          //NCON
            value = [elem objectForKey:@"update"];
            if (!value) {
                value = [NSString stringWithFormat:@"%@ is now a connection.", [elem objectForKey:@"name"]];
            }
            [elem setObject:value forKey:@"update"];
        } else if ([updateType isEqualToString:@"CCEM"]) {                          //CCEM
            value = [elem objectForKey:@"update"];
            if (!value) {
                value = [NSString stringWithFormat:@"%@ has joined LinkedIn.", [elem objectForKey:@"name"]];
            }
            [elem setObject:value forKey:@"update"];
        } else if ([updateType isEqualToString:@"QSTN"]) {                          //!TODO fix needed: QSTN
            value = [elem objectForKey:@"update"];
            if (!value) {
                value = [NSString stringWithFormat:@"%@ has asked a Question: ", [elem objectForKey:@"name"]];
                NSString *qTitle = [elem valueForKeyPath:@"updateContent.question.title"];
                if (qTitle) {
                    value = [value stringByAppendingFormat:@" <a href='%@'>%@</a>", [elem valueForKeyPath:@"updateContent.question.webUrl"], qTitle];
                }
            }
            [elem setObject:value forKey:@"update"];
        } else if ([updateType isEqualToString:@"PRFX"]) {                          //PRFX
            value = [elem objectForKey:@"update"];
            if (!value) {
                value = [NSString stringWithFormat:@"%@ has updated his extended profile.", [elem objectForKey:@"name"]];
            }
            [elem setObject:value forKey:@"update"];
        } else if ([updateType isEqualToString:@"PREC"]) {                          //PREC
            value = [elem objectForKey:@"update"];
            if (!value) {
                NSString *rName = [NSString stringWithFormat:@"%@ %@",
                                                             [elem valueForKeyPath:@"updateContent.person.recommendationsGiven.recommendation.recommendee.firstName"],
                                                             [elem valueForKeyPath:@"updateContent.person.recommendationsGiven.recommendation.recommendee.lastName"]];
                NSString *snippet = [elem valueForKeyPath:@"updateContent.person.recommendationsGiven.recommendation.recommendationSnippet"];
                value = [NSString stringWithFormat:@"%@ recommends %@: %@", [elem objectForKey:@"name"], rName, snippet];
            }
            [elem setObject:value forKey:@"update"];
        } else if ([updateType isEqualToString:@"SHAR"]) {                          //SHAR
            value = [elem objectForKey:@"update"];
            if (!value) {
                value = [NSString stringWithFormat:@"%@ %@", [elem valueForKeyPath:@"updateContent.currentShare.comment"]];
                NSString *contentTitle = [elem valueForKeyPath:@"updateContent.currentShare.content.title"];
                if (contentTitle) {
                    value = [value stringByAppendingFormat:@" <a href='%@'>%@</a>", [elem valueForKeyPath:@"updateContent.currentShare.content.submittedUrl"], contentTitle];
                }
            }
            [elem setObject:value forKey:@"update"];
        } else {
            [elem setObject:@"has shared some updates on Linkedin." forKey:@"update"];
        }
        [elem setObject:@"YES" forKey:@"prepared"];
    }
}

- (void)prepareObjectsThenRefreshView {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    [self.activeUpdates retain];
    for (NSDictionary *anUpdate in self.activeUpdates) {
        [self prepareUpdateForUse:anUpdate];
    }
    [self.activeUpdates release];
    [pool release];
    [self performSelectorOnMainThread:@selector(refreshUpdatesInView) withObject:nil waitUntilDone:NO];
}

- (void)_reloadUpdates:(BOOL)force {
    int count = 5;
    if (NSNumber *n = [self.plugin.preferences objectForKey:@"MaxUpdates"])
        count = n.intValue;
    NSLog(@"LI:LinkedIn: Fetching network updates...");
    if ([self loadUpdates:@"https://api.linkedin.com/v1/people/~/network/updates" parameters:
            [NSDictionary dictionaryWithObjectsAndKeys:[NSString stringWithFormat:@"%d", count], @"count",
                                                       [NSString stringWithFormat:@"%.0f", force ? 0 : lastFetchTime], @"after",
                                                       nil]]) {
        NSMutableArray *temp = [self.networkStream objectForKey:@"values"];
        int uCount = temp.count;
        NSLog(@"LI:LinkedIn: Received %d updates.", uCount);
        if (uCount > 0) {
            int max = 5;
            if (NSNumber *n = [self.plugin.preferences objectForKey:@"MaxUpdates"])
                max = n.intValue;
            temp = [NSMutableArray arrayWithArray:[temp sortedArrayUsingFunction:sortByDate context:nil]];
            if (!force && self.activeUpdates != nil && self.activeUpdates.count > 0 && temp.count < max) {
                for (NSDictionary *anUpdate in temp) {
                    [self.activeUpdates insertObject:anUpdate atIndex:0];
                    if (self.activeUpdates.count > max) {
                        [self.activeUpdates removeObjectAtIndex:(self.activeUpdates.count - 1)];
                    }
                }
            } else {
                self.activeUpdates = temp;
            }
            lastFetchTime = [[NSDate date] timeIntervalSince1970] * 1000;//next time we'll fetch updates only after this time
            [self performSelectorInBackground:@selector(prepareObjectsThenRefreshView) withObject:nil];
        }
        [self.networkStream removeAllObjects];
    }

    NSTimeInterval refresh = 900;
    if (NSNumber *n = [self.plugin.preferences objectForKey:@"RefreshInterval"])
        refresh = n.intValue;
    nextUpdate = [[NSDate dateWithTimeIntervalSinceNow:refresh] timeIntervalSinceReferenceDate];
}

- (void)reloadUpdates:(BOOL)force {
    if (!self.plugin.enabled)
        return;

    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    if ([lock tryLock]) {
        if (force || nextUpdate < [NSDate timeIntervalSinceReferenceDate])
            [self _reloadUpdates:force];

        [lock unlock];
    }

    [pool release];
}

- (void)update:(NSNotification *)notif {
    [self reloadUpdates:NO];
}

- (void)tableView:(LITableView *)tv reloadDataInSection:(NSInteger)section {
    [self reloadUpdates:YES];
}

- (CGFloat)tableView:(LITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    unsigned int row = indexPath.row;// - 1;
    if (row >= self.activeUpdates.count)
        return 0;

    NSMutableDictionary *elem = [self.activeUpdates objectAtIndex:row];
    [self prepareUpdateForUse:elem];

    NSString *text = [elem objectForKey:@"update"];
    if (text == nil) {
        text = @" ";
    }
    int width = (int) (tableView.frame.size.width - 100);
    CGSize s = [text sizeWithFont:tableView.theme.detailStyle.font constrainedToSize:CGSizeMake(width, tableView.theme.summaryStyle.font.leading * 2) lineBreakMode:UILineBreakModeTailTruncation];
    int height = (int) (s.height + tableView.theme.summaryStyle.font.pointSize + 10);
    return (height < 45 ? 45 : height);// > 55 ? 55 : height);

}

- (NSInteger)tableView:(UITableView *)tableView numberOfItemsInSection:(NSInteger)section {
    int max = 5;
    if (NSNumber *n = [self.plugin.preferences objectForKey:@"MaxUpdates"])
        max = n.intValue;
    return (self.activeUpdates.count > max ? max : self.activeUpdates.count);
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return [self tableView:tableView numberOfItemsInSection:section];// + 1;
}

- (UIView *)tableView:(LITableView *)tableView previewWithFrame:(CGRect)frame forRowAtIndexPath:(NSIndexPath *)indexPath {
    unsigned int row = indexPath.row;

    if (row < self.activeUpdates.count) {
        BOOL showPreview = YES;
        if (NSNumber *n = [self.plugin.preferences objectForKey:@"ShowPreview"])
            showPreview = n.boolValue;

        BOOL useDoubleTap = NO;
        if (NSNumber *n = [self.plugin.preferences objectForKey:@"UseDoubleTap"])
            useDoubleTap = n.boolValue;
        if (showPreview) {
            if (useDoubleTap) {
                tapCount++;
                if (tapCount == 2) {
                    tapCount = 0;
                    return [self showDetailView:[self.activeUpdates objectAtIndex:row]];
                }
                else {
                    [self performSelector:@selector(resetTapCount) withObject:nil afterDelay:.4];
                    return nil;
                }
            }
            else {
                return [self showDetailView:[self.activeUpdates objectAtIndex:row]];
            }
        }
    }
    return nil;
}

- (UITableViewCell *)tableView:(LITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    unsigned int row = indexPath.row;

    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"updateCell"];

    if (cell == nil) {
        CGRect frame = CGRectMake(0, 0, tableView.frame.size.width, 40);
        cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"updateCell"] autorelease];
        cell.frame = frame;

        UIView *borderView = [[[UIView alloc] initWithFrame:CGRectMake(0, 0, tableView.frame.size.width, 1)] autorelease];
        borderView.backgroundColor = UIColorFromRGBA(0xEEEEEE, 0.1);
        borderView.autoresizingMask = UIViewAutoresizingFlexibleTopMargin | UIViewAutoresizingFlexibleBottomMargin;
        [cell addSubview:borderView];
        borderView.tag = 58;

        UpdateSummaryView *v = [[[UpdateSummaryView alloc] initWithFrame:frame] autorelease];
        v.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        v.backgroundColor = [UIColor clearColor];
        v.tag = 57;
        [cell.contentView addSubview:v];

    }
    NSMutableDictionary *elem = [self.activeUpdates objectAtIndex:row];
    [self prepareUpdateForUse:elem];

    UpdateSummaryView *v = (UpdateSummaryView *) [cell.contentView viewWithTag:57];
    v.theme = tableView.theme;
    v.frame = CGRectMake(0, 0, tableView.frame.size.width, [self tableView:tableView heightForRowAtIndexPath:indexPath]);
    v.name = @"";
    v.update = @"";
    v.time = @"";

    if (row < self.activeUpdates.count) {
        v.name = [elem objectForKey:@"name"];
        NSNumber *dateNum = [[[NSNumber alloc] initWithDouble:[[elem objectForKey:@"timestamp"] doubleValue] / 1000] autorelease];
        v.time = [self timeToString:dateNum];
        [elem setObject:v.time forKey:@"time"]; //so that detail view doesn't have to re-calculate it.
        v.image = [self.imageCache objectForKey:[elem objectForKey:@"pictureUrl"]];
        v.update = [elem objectForKey:@"update"];
    }
    [v setNeedsDisplay];
    return cell;
}

- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType {
    NSURL *url = request.URL;
    [self.plugin launchURL:url];
    return NO;
}

- (void)webViewDidStartLoad:(UIWebView *)webView {
    [self.activity startAnimating];
    webView.hidden = YES;
}

- (void)webViewDidFinishLoad:(UIWebView *)aWebView {
    CGRect frame = aWebView.frame;
    frame.size.height = 1;
    aWebView.frame = frame;
    CGSize fittingSize = [aWebView sizeThatFits:CGSizeZero];
    frame.size = fittingSize;
    aWebView.frame = frame;
    aWebView.hidden = NO;
    [self performSelector:@selector(addConnViewsAndUpdateHeight) withObject:nil afterDelay:0];
}

- (void)addConnViewsAndUpdateHeight {
    UIScrollView *scrollView = (UIScrollView *) [self.readView viewWithTag:101];
    UIWebView *aWebView = (UIWebView *) [self.readView viewWithTag:102];
    NSString *updateType = [self.selectedUpdate objectForKey:@"updateType"];
    if ([updateType isEqualToString:@"CONN"]) {                         //CONN
        NSArray *connections = [self.selectedUpdate valueForKeyPath:@"updateContent.person.connections.values"];
        for (int i = 0, length = connections ? [connections count] : 0; i < length; i++) {
            NSDictionary *connection = [connections objectAtIndex:i];
            NSString *connectionName = [NSString stringWithFormat:@"%@ %@", [connection objectForKey:@"firstName"], [connection objectForKey:@"lastName"]];
            NSString *headline = [connection objectForKey:@"headline"];
            NSString *url = [connection objectForKey:@"pictureUrl"];
            if (!url) {url = NO_IMG_URL;}
            UIImage *image = [self.imageCache objectForKey:url];
            if (!image) {
                image = [UIImage imageWithData:[NSData dataWithContentsOfURL:[NSURL URLWithString:[[url copy] autorelease]]]];
                [self.imageCache setValue:image forKey:url];
            }
            int tag = 200 + i;
            ProfileHeadingView *headingView = (ProfileHeadingView *) [scrollView viewWithTag:tag];
            if (headingView == nil) {
                headingView = [[[ProfileHeadingView alloc] initWithName:connectionName headline:headline image:image] autorelease];
                headingView.frame = CGRectMake(0, aWebView.frame.origin.y + aWebView.frame.size.height + 10 + i * 84, scrollView.frame.size.width, 84);
                headingView.tag = tag;
                [headingView sizeToFit];
                headingView.backgroundColor = UIColorFromRGB(0xDDDDDD);
                headingView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleTopMargin;
                headingView.layer.borderWidth = 1.0;
                headingView.layer.borderColor = [[UIColor grayColor] CGColor];
                [scrollView insertSubview:headingView atIndex:1]; //after webview
            } else {
                headingView.name = connectionName;
                headingView.headline = headline;
                headingView.image = image;
            }
            headingView.hidden = NO;
            [headingView setNeedsDisplay];
        }
    }
    [self adjustScrollViewHeight];
    [self.activity stopAnimating];
}
@end
