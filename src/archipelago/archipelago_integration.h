// archipelago_integration.h
// Selaco-specific Archipelago integration

#pragma once

#ifdef ARCHIPELAGO_SUPPORT

#include "archipelago_protocol.h"
#include <memory>
#include <string>

// Forward declarations
class player_t;

namespace Archipelago {

class SelacoArchipelago {
public:
    static SelacoArchipelago& GetInstance();
    
    // Initialize the Archipelago client
    void Initialize();
    void Shutdown();
    
    // Connect to server
    bool Connect(const std::string& server, int port = 38281);
    void Disconnect();
    bool IsConnected() const;
    
    // Authentication
    void Authenticate(const std::string& slot_name, const std::string& password = "");
    
    // Game events
    void OnLocationChecked(int64_t location_id);
    void OnItemReceived(int64_t item_id, const std::string& item_name, const std::string& sender);
    void OnPlayerDeath();
    void OnLevelComplete(const std::string& level_name);
    
    // Update (call from game loop)
    void Update();
    
    // Console commands
    void ProcessConsoleCommand(const std::string& command);
    
private:
    SelacoArchipelago();
    ~SelacoArchipelago();
    
    // Callbacks from Archipelago client
    void OnConnectedToRoom();
    void OnItemsReceived(const std::vector<NetworkItem>& items);
    void OnPrintJson(const json& message);
    
    std::unique_ptr<ArchipelagoClient> client_;
    bool initialized_;
    
    // Game state
    player_t* local_player_;
    std::vector<int64_t> checked_locations_;
    std::vector<int64_t> received_items_;
};

} // namespace Archipelago

// C-style interface for game code
extern "C" {
    void AP_Initialize();
    void AP_Shutdown();
    void AP_Update();
    bool AP_Connect(const char* server, int port);
    void AP_Disconnect();
    bool AP_IsConnected();
    void AP_Authenticate(const char* slot_name, const char* password);
    void AP_LocationChecked(int64_t location_id);
    void AP_ProcessCommand(const char* command);
}

#endif // ARCHIPELAGO_SUPPORT
