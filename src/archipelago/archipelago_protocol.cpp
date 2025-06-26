// archipelago_protocol.cpp
// Archipelago Protocol Implementation

#include "archipelago_protocol.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace Archipelago {

// Logging helpers (matching websocket implementation)
#define AP_LOG_ERROR(fmt, ...) printf("[AP-ERROR] " fmt "\n", ##__VA_ARGS__)
#define AP_LOG_INFO(fmt, ...) printf("[AP-INFO] " fmt "\n", ##__VA_ARGS__)
#define AP_LOG_DEBUG(fmt, ...) // printf("[AP-DEBUG] " fmt "\n", ##__VA_ARGS__)

ArchipelagoClient::ArchipelagoClient()
    : authenticated_(false)
    , game_name_("Selaco")
    , team_(-1)
    , slot_(-1)
    , hint_points_(0) {
    
    // Setup WebSocket callbacks
    ws_client_.SetConnectedCallback([this]() { OnWebSocketConnected(); });
    ws_client_.SetDisconnectedCallback([this](int code, const std::string& reason) { 
        OnWebSocketDisconnected(code, reason); 
    });
    ws_client_.SetMessageCallback([this](const json& msg) { OnWebSocketMessage(msg); });
    ws_client_.SetErrorCallback([this](const std::string& error) { OnWebSocketError(error); });
    
    // Generate UUID for this session
    uuid_ = GenerateUUID();
}

ArchipelagoClient::~ArchipelagoClient() {
    Disconnect();
}

bool ArchipelagoClient::Connect(const std::string& host, int port, bool use_ssl) {
    AP_LOG_INFO("Connecting to Archipelago server at %s:%d", host.c_str(), port);
    return ws_client_.Connect(host, port, use_ssl);
}

void ArchipelagoClient::Disconnect() {
    authenticated_ = false;
    ws_client_.Disconnect();
}

void ArchipelagoClient::Authenticate(const std::string& slot_name, 
                                   const std::string& password,
                                   const std::string& game) {
    if (!ws_client_.IsConnected()) {
        AP_LOG_ERROR("Cannot authenticate - not connected");
        return;
    }
    
    slot_name_ = slot_name;
    password_ = password;
    game_name_ = game;
    
    // Build Connect packet
    json connect_packet = {
        {"cmd", "Connect"},
        {"password", password_},
        {"game", game_name_},
        {"name", slot_name_},
        {"uuid", uuid_},
        {"version", Version().ToJson()},
        {"items_handling", ITEMS_HANDLING_ALL},
        {"tags", json::array({"AP", "CPPClient", "Selaco"})}
    };
    
    AP_LOG_INFO("Authenticating as slot '%s' for game '%s'", slot_name.c_str(), game.c_str());
    SendPacketArray({connect_packet});
}

void ArchipelagoClient::SendLocationChecks(const std::vector<int64_t>& location_ids) {
    if (!IsAuthenticated()) {
        AP_LOG_ERROR("Cannot send location checks - not authenticated");
        return;
    }
    
    json packet = {
        {"cmd", "LocationChecks"},
        {"locations", location_ids}
    };
    
    AP_LOG_DEBUG("Sending location checks: %zu locations", location_ids.size());
    SendPacketArray({packet});
}

void ArchipelagoClient::SendLocationScouts(const std::vector<int64_t>& location_ids, int hint_points) {
    if (!IsAuthenticated()) {
        AP_LOG_ERROR("Cannot send location scouts - not authenticated");
        return;
    }
    
    json packet = {
        {"cmd", "LocationScouts"},
        {"locations", location_ids},
        {"create_as_hint", hint_points}
    };
    
    SendPacketArray({packet});
}

void ArchipelagoClient::SendStatusUpdate(ClientStatus status) {
    if (!IsAuthenticated()) {
        return;
    }
    
    json packet = {
        {"cmd", "StatusUpdate"},
        {"status", static_cast<int>(status)}
    };
    
    SendPacketArray({packet});
}

void ArchipelagoClient::SendChat(const std::string& message) {
    if (!IsAuthenticated()) {
        AP_LOG_ERROR("Cannot send chat - not authenticated");
        return;
    }
    
    json packet = {
        {"cmd", "Say"},
        {"text", message}
    };
    
    SendPacketArray({packet});
}

void ArchipelagoClient::RequestDataPackage(const std::vector<std::string>& games) {
    json packet = {
        {"cmd", "GetDataPackage"}
    };
    
    if (!games.empty()) {
        packet["games"] = games;
    }
    
    AP_LOG_INFO("Requesting data package");
    SendPacketArray({packet});
}

// WebSocket event handlers
void ArchipelagoClient::OnWebSocketConnected() {
    AP_LOG_INFO("WebSocket connected, waiting for RoomInfo");
    authenticated_ = false;
}

void ArchipelagoClient::OnWebSocketDisconnected(int code, const std::string& reason) {
    AP_LOG_INFO("WebSocket disconnected: %d - %s", code, reason.c_str());
    authenticated_ = false;
    
    // Clear server data
    team_ = -1;
    slot_ = -1;
    players_.clear();
    seed_name_.clear();
    slot_data_.clear();
}

void ArchipelagoClient::OnWebSocketMessage(const json& message) {
    try {
        // Archipelago sends arrays of packets
        if (message.is_array()) {
            for (const auto& packet : message) {
                HandlePacket(packet);
            }
        } else {
            // Single packet (shouldn't happen but handle it)
            HandlePacket(message);
        }
    } catch (const std::exception& e) {
        AP_LOG_ERROR("Error handling message: %s", e.what());
    }
}

void ArchipelagoClient::OnWebSocketError(const std::string& error) {
    AP_LOG_ERROR("WebSocket error: %s", error.c_str());
}

// Packet handlers
void ArchipelagoClient::HandlePacket(const json& packet) {
    PacketType type = GetPacketType(packet);
    
    AP_LOG_DEBUG("Handling packet type: %d", static_cast<int>(type));
    
    switch (type) {
        case PacketType::ROOM_INFO:
            HandleRoomInfo(packet);
            break;
            
        case PacketType::CONNECTION_REFUSED:
            HandleConnectionRefused(packet);
            break;
            
        case PacketType::CONNECTED:
            HandleConnected(packet);
            break;
            
        case PacketType::RECEIVED_ITEMS:
            HandleReceivedItems(packet);
            break;
            
        case PacketType::PRINT_JSON:
            HandlePrintJson(packet);
            break;
            
        case PacketType::DATA_PACKAGE:
            HandleDataPackage(packet);
            break;
            
        case PacketType::ROOM_UPDATE:
            HandleRoomUpdate(packet);
            break;
            
        default:
            AP_LOG_DEBUG("Unhandled packet type: %s", 
                        packet.value("cmd", "unknown").c_str());
            break;
    }
}

void ArchipelagoClient::HandleRoomInfo(const json& packet) {
    AP_LOG_INFO("Received RoomInfo");
    
    // Parse server version
    if (packet.contains("version")) {
        auto ver = packet["version"];
        server_version_.major = ver.value("major", 0);
        server_version_.minor = ver.value("minor", 0);
        server_version_.build = ver.value("build", 0);
    }
    
    // Parse other info
    if (packet.contains("seed_name")) {
        seed_name_ = packet["seed_name"];
    }
    
    // Notify callback
    if (on_room_info_) {
        on_room_info_(packet);
    }
    
    // If we have credentials, authenticate now
    if (!slot_name_.empty()) {
        Authenticate(slot_name_, password_, game_name_);
    }
}

void ArchipelagoClient::HandleConnectionRefused(const json& packet) {
    AP_LOG_ERROR("Connection refused by server");
    
    ConnectionResult result = ConnectionResult::INVALID_SLOT;
    
    if (packet.contains("errors")) {
        auto errors = packet["errors"];
        if (errors.contains("InvalidSlot")) {
            result = ConnectionResult::INVALID_SLOT;
            AP_LOG_ERROR("Invalid slot name");
        } else if (errors.contains("InvalidGame")) {
            result = ConnectionResult::INVALID_GAME;
            AP_LOG_ERROR("Invalid game");
        } else if (errors.contains("IncompatibleVersion")) {
            result = ConnectionResult::INCOMPATIBLE_VERSION;
            AP_LOG_ERROR("Incompatible version");
        } else if (errors.contains("InvalidPassword")) {
            result = ConnectionResult::INVALID_PASSWORD;
            AP_LOG_ERROR("Invalid password");
        } else if (errors.contains("InvalidItemsHandling")) {
            result = ConnectionResult::INVALID_ITEMS_HANDLING;
            AP_LOG_ERROR("Invalid items handling");
        }
    }
    
    authenticated_ = false;
    
    if (on_connected_result_) {
        on_connected_result_(result);
    }
}

void ArchipelagoClient::HandleConnected(const json& packet) {
    AP_LOG_INFO("Successfully connected to Archipelago");
    
    authenticated_ = true;
    
    // Parse connection info
    team_ = packet.value("team", -1);
    slot_ = packet.value("slot", -1);
    hint_points_ = packet.value("hint_points", 0);
    
    // Parse players list
    if (packet.contains("players")) {
        players_.clear();
        for (const auto& player : packet["players"]) {
            if (player.contains("name")) {
                players_.push_back(player["name"]);
            }
        }
    }
    
    // Parse slot data
    if (packet.contains("slot_data")) {
        slot_data_.clear();
        for (auto& [key, value] : packet["slot_data"].items()) {
            if (value.is_string()) {
                slot_data_[key] = value;
            } else {
                slot_data_[key] = value.dump();
            }
        }
    }
    
    AP_LOG_INFO("Connected as player %d (slot %d) in team %d", 
                slot_, slot_, team_);
    
    // Update status to playing
    SendStatusUpdate(ClientStatus::CLIENT_PLAYING);
    
    if (on_connected_result_) {
        on_connected_result_(ConnectionResult::SUCCESS);
    }
}

void ArchipelagoClient::HandleReceivedItems(const json& packet) {
    std::vector<NetworkItem> items;
    
    if (packet.contains("items")) {
        for (const auto& item_json : packet["items"]) {
            NetworkItem item;
            item.item_id = item_json.value("item", 0);
            item.location_id = item_json.value("location", 0);
            item.player_id = item_json.value("player", 0);
            item.flags = item_json.value("flags", 0);
            
            // Get names if available
            if (item_data_.count(item.item_id)) {
                item.item_name = item_data_[item.item_id].name;
            }
            if (location_data_.count(item.location_id)) {
                item.location_name = location_data_[item.location_id].name;
            }
            if (item.player_id >= 0 && item.player_id < static_cast<int>(players_.size())) {
                item.player_name = players_[item.player_id];
            }
            
            items.push_back(item);
        }
    }
    
    AP_LOG_INFO("Received %zu items", items.size());
    
    if (on_items_received_ && !items.empty()) {
        on_items_received_(items);
    }
}

void ArchipelagoClient::HandlePrintJson(const json& packet) {
    if (on_print_json_) {
        on_print_json_(packet);
    }
}

void ArchipelagoClient::HandleDataPackage(const json& packet) {
    AP_LOG_INFO("Received data package");
    
    // Parse games data
    if (packet.contains("data") && packet["data"].contains("games")) {
        for (auto& [game_name, game_data] : packet["data"]["games"].items()) {
            if (game_name != game_name_) {
                continue; // Only interested in our game
            }
            
            // Parse item names
            if (game_data.contains("item_name_to_id")) {
                for (auto& [name, id] : game_data["item_name_to_id"].items()) {
                    ItemInfo info;
                    info.name = name;
                    info.id = id;
                    info.classification = 0; // Default
                    item_data_[info.id] = info;
                }
            }
            
            // Parse location names
            if (game_data.contains("location_name_to_id")) {
                for (auto& [name, id] : game_data["location_name_to_id"].items()) {
                    LocationInfo info;
                    info.name = name;
                    info.id = id;
                    location_data_[info.id] = info;
                }
            }
        }
    }
    
    AP_LOG_INFO("Loaded %zu items and %zu locations for %s", 
                item_data_.size(), location_data_.size(), game_name_.c_str());
    
    if (on_data_package_) {
        on_data_package_(packet);
    }
}

void ArchipelagoClient::HandleRoomUpdate(const json& packet) {
    // Update room info based on changes
    if (packet.contains("hint_points")) {
        hint_points_ = packet["hint_points"];
    }
    
    // Could handle other updates here
}

// Helpers
PacketType ArchipelagoClient::GetPacketType(const json& packet) {
    if (!packet.contains("cmd")) {
        return PacketType::UNKNOWN;
    }
    
    std::string cmd = packet["cmd"];
    
    // Map command strings to packet types
    static const std::map<std::string, PacketType> packet_map = {
        {"RoomInfo", PacketType::ROOM_INFO},
        {"ConnectionRefused", PacketType::CONNECTION_REFUSED},
        {"Connected", PacketType::CONNECTED},
        {"ReceivedItems", PacketType::RECEIVED_ITEMS},
        {"LocationInfo", PacketType::LOCATION_INFO},
        {"RoomUpdate", PacketType::ROOM_UPDATE},
        {"PrintJSON", PacketType::PRINT_JSON},
        {"DataPackage", PacketType::DATA_PACKAGE},
        {"SetReply", PacketType::SET_REPLY},
        {"Bounced", PacketType::BOUNCED}
    };
    
    auto it = packet_map.find(cmd);
    if (it != packet_map.end()) {
        return it->second;
    }
    
    return PacketType::UNKNOWN;
}

std::string ArchipelagoClient::GenerateUUID() {
    // Simple UUID v4 generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::uniform_int_distribution<> dis2(8, 11);
    
    std::stringstream ss;
    ss << std::hex;
    
    for (int i = 0; i < 8; i++) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 4; i++) ss << dis(gen);
    ss << "-4"; // Version 4
    for (int i = 0; i < 3; i++) ss << dis(gen);
    ss << "-";
    ss << dis2(gen); // Variant
    for (int i = 0; i < 3; i++) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 12; i++) ss << dis(gen);
    
    return ss.str();
}

void ArchipelagoClient::SendPacket(const json& packet) {
    ws_client_.SendJSON(packet);
}

void ArchipelagoClient::SendPacketArray(const json& packets) {
    // Archipelago expects an array of packets
    ws_client_.SendJSON(packets);
}

} // namespace Archipelago
