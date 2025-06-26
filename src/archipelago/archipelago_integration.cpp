// archipelago_integration.cpp
// Selaco-specific Archipelago integration implementation

#ifdef ARCHIPELAGO_SUPPORT

#include "archipelago_integration.h"
#include <iostream>
#include <sstream>

namespace Archipelago {

SelacoArchipelago& SelacoArchipelago::GetInstance() {
    static SelacoArchipelago instance;
    return instance;
}

SelacoArchipelago::SelacoArchipelago() 
    : initialized_(false)
    , local_player_(nullptr) {
}

SelacoArchipelago::~SelacoArchipelago() {
    Shutdown();
}

void SelacoArchipelago::Initialize() {
    if (initialized_) {
        return;
    }
    
    std::cout << "[Archipelago] Initializing Selaco Archipelago client..." << std::endl;
    
    client_ = std::make_unique<ArchipelagoClient>();
    
    // Setup callbacks
    client_->SetConnectedCallback([this](ConnectionResult result) {
        if (result == ConnectionResult::SUCCESS) {
            OnConnectedToRoom();
        } else {
            std::cout << "[Archipelago] Failed to authenticate!" << std::endl;
        }
    });
    
    client_->SetItemsReceivedCallback([this](const std::vector<NetworkItem>& items) {
        OnItemsReceived(items);
    });
    
    client_->SetPrintJsonCallback([this](const json& message) {
        OnPrintJson(message);
    });
    
    initialized_ = true;
    std::cout << "[Archipelago] Initialization complete" << std::endl;
}

void SelacoArchipelago::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    std::cout << "[Archipelago] Shutting down..." << std::endl;
    
    if (client_) {
        client_->Disconnect();
        client_.reset();
    }
    
    initialized_ = false;
}

bool SelacoArchipelago::Connect(const std::string& server, int port) {
    if (!initialized_) {
        Initialize();
    }
    
    std::cout << "[Archipelago] Connecting to " << server << ":" << port << std::endl;
    return client_->Connect(server, port);
}

void SelacoArchipelago::Disconnect() {
    if (client_) {
        client_->Disconnect();
    }
}

bool SelacoArchipelago::IsConnected() const {
    return client_ && client_->IsConnected();
}

void SelacoArchipelago::Authenticate(const std::string& slot_name, const std::string& password) {
    if (!client_ || !client_->IsConnected()) {
        std::cout << "[Archipelago] Cannot authenticate - not connected!" << std::endl;
        return;
    }
    
    std::cout << "[Archipelago] Authenticating as " << slot_name << std::endl;
    client_->Authenticate(slot_name, password, "Selaco");
}

void SelacoArchipelago::OnLocationChecked(int64_t location_id) {
    if (!client_ || !client_->IsAuthenticated()) {
        return;
    }
    
    // Avoid duplicate checks
    if (std::find(checked_locations_.begin(), checked_locations_.end(), location_id) 
        != checked_locations_.end()) {
        return;
    }
    
    checked_locations_.push_back(location_id);
    client_->SendLocationChecks({location_id});
    
    std::cout << "[Archipelago] Location checked: " << location_id << std::endl;
}

void SelacoArchipelago::Update() {
    if (client_) {
        client_->Service();
    }
}

void SelacoArchipelago::OnConnectedToRoom() {
    std::cout << "[Archipelago] Successfully connected to room!" << std::endl;
    std::cout << "[Archipelago] Seed: " << client_->GetSeed() << std::endl;
    std::cout << "[Archipelago] Slot: " << client_->GetSlot() << std::endl;
    
    // Request data package for our game
    client_->RequestDataPackage({"Selaco"});
}

void SelacoArchipelago::OnItemsReceived(const std::vector<NetworkItem>& items) {
    for (const auto& item : items) {
        std::cout << "[Archipelago] Received item: " << item.item_name 
                  << " from " << item.player_name << std::endl;
        
        // TODO: Give item to player based on item_id
        OnItemReceived(item.item_id, item.item_name, item.player_name);
    }
}

void SelacoArchipelago::OnPrintJson(const json& message) {
    // Handle print messages from server
    if (message.contains("text")) {
        std::cout << "[Archipelago] " << message["text"] << std::endl;
    }
}

void SelacoArchipelago::OnItemReceived(int64_t item_id, const std::string& item_name, 
                                      const std::string& sender) {
    // TODO: Implement item giving logic
    // This is where you'd interface with Selaco's item system
    
    received_items_.push_back(item_id);
}

void SelacoArchipelago::ProcessConsoleCommand(const std::string& command) {
    std::istringstream iss(command);
    std::string cmd;
    iss >> cmd;
    
    if (cmd == "connect") {
        std::string server;
        int port = 38281;
        iss >> server;
        if (iss >> port) {
            // Port specified
        }
        Connect(server, port);
    } else if (cmd == "disconnect") {
        Disconnect();
    } else if (cmd == "auth" || cmd == "authenticate") {
        std::string slot, password;
        iss >> slot;
        iss >> password; // Optional
        Authenticate(slot, password);
    } else if (cmd == "status") {
        std::cout << "[Archipelago] Connected: " << (IsConnected() ? "Yes" : "No") << std::endl;
        if (client_ && client_->IsAuthenticated()) {
            std::cout << "[Archipelago] Authenticated as slot " << client_->GetSlot() << std::endl;
        }
    } else {
        std::cout << "[Archipelago] Unknown command: " << cmd << std::endl;
    }
}

} // namespace Archipelago

// C-style interface implementation
extern "C" {

void AP_Initialize() {
    Archipelago::SelacoArchipelago::GetInstance().Initialize();
}

void AP_Shutdown() {
    Archipelago::SelacoArchipelago::GetInstance().Shutdown();
}

void AP_Update() {
    Archipelago::SelacoArchipelago::GetInstance().Update();
}

bool AP_Connect(const char* server, int port) {
    return Archipelago::SelacoArchipelago::GetInstance().Connect(server, port);
}

void AP_Disconnect() {
    Archipelago::SelacoArchipelago::GetInstance().Disconnect();
}

bool AP_IsConnected() {
    return Archipelago::SelacoArchipelago::GetInstance().IsConnected();
}

void AP_Authenticate(const char* slot_name, const char* password) {
    Archipelago::SelacoArchipelago::GetInstance().Authenticate(
        slot_name, password ? password : "");
}

void AP_LocationChecked(int64_t location_id) {
    Archipelago::SelacoArchipelago::GetInstance().OnLocationChecked(location_id);
}

void AP_ProcessCommand(const char* command) {
    Archipelago::SelacoArchipelago::GetInstance().ProcessConsoleCommand(command);
}

} // extern "C"

#endif // ARCHIPELAGO_SUPPORT
