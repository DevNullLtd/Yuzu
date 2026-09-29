/**
 * wifi_corewlan.mm — Objective-C++ implementation of the macOS current-Wi-Fi
 * query declared in wifi_corewlan.hpp.
 *
 * FIRST Objective-C++ (`.mm`) translation unit in the Yuzu tree. CoreWLAN is a
 * public framework shipped in the base macOS SDK (present with the Command Line
 * Tools SDK), so this always compiles on a dev box. Built with `-fobjc-arc`;
 * only reads autoreleased objects, so no manual retain/release. See
 * agents/plugins/wifi/meson.build.
 */

#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>

#include "wifi_corewlan.hpp"

namespace yuzu::wifi {

namespace {

std::string security_to_string(CWSecurity sec) {
    switch (sec) {
    case kCWSecurityNone:
        return "Open";
    case kCWSecurityWEP:
        return "WEP";
    case kCWSecurityWPAPersonal:
        return "WPA-Personal";
    case kCWSecurityWPAPersonalMixed:
        return "WPA/WPA2-Personal";
    case kCWSecurityWPA2Personal:
        return "WPA2-Personal";
    case kCWSecurityPersonal:
        return "Personal";
    case kCWSecurityDynamicWEP:
        return "Dynamic-WEP";
    case kCWSecurityWPAEnterprise:
        return "WPA-Enterprise";
    case kCWSecurityWPAEnterpriseMixed:
        return "WPA/WPA2-Enterprise";
    case kCWSecurityWPA2Enterprise:
        return "WPA2-Enterprise";
    case kCWSecurityEnterprise:
        return "Enterprise";
    case kCWSecurityWPA3Personal:
        return "WPA3-Personal";
    case kCWSecurityWPA3Enterprise:
        return "WPA3-Enterprise";
    case kCWSecurityWPA3Transition:
        return "WPA3-Transition";
    case kCWSecurityOWE:
        return "OWE";
    case kCWSecurityOWETransition:
        return "OWE-Transition";
    default:
        return ""; // kCWSecurityUnknown and anything newer than this SDK knows
    }
}

std::string to_std(NSString* s) {
    if (s == nil)
        return {};
    const char* utf8 = s.UTF8String;
    return utf8 ? std::string(utf8) : std::string{};
}

} // namespace

bool corewlan_current_connection(WifiConnection& out) {
    @autoreleasepool {
        // CoreWLAN getters are read-only and don't throw in practice, but an
        // ObjC exception unwinding through these ARC/C++ frames would be
        // implementation-defined (risking std::terminate of the agent). Contain
        // it: on any exception, report no interface (→ honest "Not connected").
        @try {
        CWWiFiClient* client = [CWWiFiClient sharedWiFiClient];
        if (client == nil)
            return false;

        CWInterface* iface = [client interface];
        if (iface == nil)
            return false; // no Wi-Fi hardware

        out.interface = to_std(iface.interfaceName);
        out.power_on = iface.powerOn;

        // A non-nil channel is the authorisation-free signal that the interface
        // has actually joined a network; ssid/bssid can be withheld, the channel
        // cannot. rssiValue is 0 and wlanChannel nil when unassociated.
        CWChannel* channel = iface.wlanChannel;
        out.associated = (channel != nil);
        if (channel != nil)
            out.channel = static_cast<int>(channel.channelNumber);

        if (out.associated) {
            out.rssi = static_cast<int>(iface.rssiValue);
            out.security = security_to_string(iface.security);

            // Treat the SSID as available only if we actually decoded a
            // non-empty name. iface.ssid is nil in more than one case and we
            // CANNOT distinguish them from here: Location-Services withholding
            // (the common case for a background daemon on 14+), a legitimately
            // joined hidden SSID, or a non-UTF8 SSID (UTF8String → nil → empty).
            // Any of them falls back to the "<ssid-withheld>" marker rather than
            // emitting a blank field — the marker means "name unavailable", and
            // Location Services is the usual but not the only reason.
            out.ssid = to_std(iface.ssid);
            out.ssid_available = !out.ssid.empty();
            out.bssid = to_std(iface.bssid); // nil → empty when name unavailable
        }

        return true;
        } @catch (NSException* e) {
            out = WifiConnection{}; // discard any partial state
            return false;
        }
    }
}

} // namespace yuzu::wifi
