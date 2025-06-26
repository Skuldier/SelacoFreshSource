// archipelago_ccmds.cpp
// Console commands for Archipelago integration

#ifdef ARCHIPELAGO_SUPPORT

#include "c_dispatch.h"
#include "c_console.h"
#include "archipelago/archipelago_integration.h"

CCMD(ap_connect)
{
    if (argv.argc() < 2) {
        Printf("Usage: ap_connect <server> [port]\n");
        return;
    }
    
    const char* server = argv[1];
    int port = 38281;
    
    if (argv.argc() >= 3) {
        port = atoi(argv[2]);
    }
    
    if (AP_Connect(server, port)) {
        Printf("Connecting to Archipelago server %s:%d...\n", server, port);
    } else {
        Printf("Failed to connect to Archipelago server\n");
    }
}

CCMD(ap_disconnect)
{
    AP_Disconnect();
    Printf("Disconnected from Archipelago\n");
}

CCMD(ap_auth)
{
    if (argv.argc() < 2) {
        Printf("Usage: ap_auth <slot_name> [password]\n");
        return;
    }
    
    const char* slot = argv[1];
    const char* password = argv.argc() >= 3 ? argv[2] : nullptr;
    
    AP_Authenticate(slot, password);
}

CCMD(ap_status)
{
    if (AP_IsConnected()) {
        Printf("Connected to Archipelago server\n");
    } else {
        Printf("Not connected to Archipelago\n");
    }
}

// Register commands on startup
struct ArchipelagoCommandRegistrar {
    ArchipelagoCommandRegistrar() {
        // Commands are automatically registered by CCMD macro
        Printf("Archipelago console commands registered\n");
    }
};

static ArchipelagoCommandRegistrar registrar;

#endif // ARCHIPELAGO_SUPPORT
