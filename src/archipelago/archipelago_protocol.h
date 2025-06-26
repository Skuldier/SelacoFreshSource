// archipelago_protocol.h
// Archipelago Protocol Implementation for Selaco

#pragma once

#include "archipelago_websocket.h"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <cstdint>

namespace Archipelago {

using json = nlohmann::json;

// Version info
struct Version {
    int major = 0;
    int minor = 5;
    int build = 0;
    
    json ToJson() const {
        return {
            {"major", major},
            {"minor", minor},
            {"build", build},
            {"class", "Version"}
        };
    }
};

// Network item structure
struct NetworkItem {
    int64_t item_id;
    int64_t location_id;
    int player_id;
    int flags;
    std::string item_name;
    std::string location_name;
    std::string player_name;
};

// Data package item info
struct ItemInfo {
    std::string name;
    int64_t id;
    int64_t classification; // 0=filler, 1=progression, 2=useful, 4=trap
};

// Data package location info  
struct LocationInfo {
    std::string name;
    int64_t id;
};

// Connection result
enum class ConnectionResult {
    SUCCESS,
    INVALID_SLOT,
    INVALID_GAME,
    INCOMPATIBLE_VERSION,
    INVALID_PASSWORD,
    INVALID_ITEMS_HANDLING
};

// Protocol packet types
enum class PacketType {
    // Server -> Client
    ROOM_INFO,
    CONNECTION_REFUSED,
    CONNECTED,
    RECEIVED_ITEMS,
    LOCATION_INFO,
    ROOM_UPDATE,
    PRINT_JSON,
    DATA_PACKAGE,
    SET_REPLY,
    
    // Client -> Server
    CONNECT,
    LOCATION_CHECKS,
    LOCATION_SCOUTS,
    STATUS_UPDATE,
    SAY,
    GET_DATA_PACKAGE,
    SET,
    SET_NOTIFY,
    
    // Bidirectional
    BOUNCE,
    BOUNCED,
    
    UNKNOWN
};

// Game status
enum class ClientStatus {
    CLIENT_UNKNOWN = 0,
    CLIENT_CONNECTED = 5,
    CLIENT_READY = 10,
    CLIENT_PLAYING = 20,
    CLIENT_GOAL_COMPLETED = 30
};

// Forward declaration
class ArchipelagoClient;

// Callback types
using RoomInfoCallback = std::function<void(const json&)>;
using ConnectedResultCallback = std::function<void(ConnectionResult)>;
using ItemsReceivedCallback = std::function<void(const std::vector<NetworkItem>&)>;
using PrintJsonCallback = std::function<void(const json&)>;
using DataPackageCallback = std::function<void(const json&)>;

class ArchipelagoClient {
public:
    ArchipelagoClient();
    ~ArchipelagoClient();
    
    // Connection management
    bool Connect(const std::string& host, int port = 38281, bool use_ssl = true);
    void Disconnect();
    bool IsConnected() const { return ws_client_.IsConnected(); }
    bool IsAuthenticated() const { return authenticated_; }
    
    // Authentication
    void Authenticate(const std::string& slot_name, 
                     const std::string& password = "",
                     const std::string& game = "Selaco");
    
    // Game actions
    void SendLocationChecks(const std::vector<int64_t>& location_ids);
    void SendLocationScouts(const std::vector<int64_t>& location_ids, int hint_points = 0);
    void SendStatusUpdate(ClientStatus status);
    void SendChat(const std::string& message);
    void RequestDataPackage(const std::vector<std::string>& games = {});
    
    // Service (call from game loop)
    void Service() { ws_client_.Service(); }
    
    // Callbacks
    void SetRoomInfoCallback(RoomInfoCallback cb) { on_room_info_ = cb; }
    void SetConnectedCallback(ConnectedResultCallback cb) { on_connected_result_ = cb; }
    void SetItemsReceivedCallback(ItemsReceivedCallback cb) { on_items_received_ = cb; }
    void SetPrintJsonCallback(PrintJsonCallback cb) { on_print_json_ = cb; }
    void SetDataPackageCallback(DataPackageCallback cb) { on_data_package_ = cb; }
    
    // Get info
    int GetTeam() const { return team_; }
    int GetSlot() const { return slot_; }
    const std::vector<std::string>& GetPlayers() const { return players_; }
    const std::string& GetSeed() const { return seed_name_; }
    
    // Data package access
    const std::map<int64_t, ItemInfo>& GetItemData() const { return item_data_; }
    const std::map<int64_t, LocationInfo>& GetLocationData() const { return location_data_; }

private:
    // WebSocket event handlers
    void OnWebSocketConnected();
    void OnWebSocketDisconnected(int code, const std::string& reason);
    void OnWebSocketMessage(const json& message);
    void OnWebSocketError(const std::string& error);
    
    // Packet handlers
    void HandlePacket(const json& packet);
    void HandleRoomInfo(const json& packet);
    void HandleConnectionRefused(const json& packet);
    void HandleConnected(const json& packet);
    void HandleReceivedItems(const json& packet);
    void HandlePrintJson(const json& packet);
    void HandleDataPackage(const json& packet);
    void HandleRoomUpdate(const json& packet);
    
    // Helpers
    PacketType GetPacketType(const json& packet);
    std::string GenerateUUID();
    void SendPacket(const json& packet);
    void SendPacketArray(const json& packets);
    
    // WebSocket client
    WebSocketClient ws_client_;
    
    // Connection state
    bool authenticated_;
    std::string slot_name_;
    std::string password_;
    std::string game_name_;
    std::string uuid_;
    
    // Server info
    Version server_version_;
    std::string seed_name_;
    int team_;
    int slot_;
    std::vector<std::string> players_;
    std::map<std::string, std::string> slot_data_;
    int hint_points_;
    
    // Data packages
    std::map<int64_t, ItemInfo> item_data_;
    std::map<int64_t, LocationInfo> location_data_;
    
    // Callbacks
    RoomInfoCallback on_room_info_;
    ConnectedResultCallback on_connected_result_;
    ItemsReceivedCallback on_items_received_;
    PrintJsonCallback on_print_json_;
    DataPackageCallback on_data_package_;
    
    // Items handling flags
    static constexpr int ITEMS_HANDLING_ALL = 0b111;
};

} // namespace Archipelago
