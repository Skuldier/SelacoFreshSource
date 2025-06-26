#!/usr/bin/env python3
"""
setup_archipelago_selaco.py - Complete one-click Archipelago setup for Selaco
This script creates all necessary files and patches Selaco for Archipelago support.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
import argparse

class ArchipelagoSelacoSetup:
    def __init__(self, selaco_dir, auto_build=False):
        self.selaco_dir = Path(selaco_dir).resolve()
        self.src_dir = self.selaco_dir / "src"
        self.archipelago_dir = self.src_dir / "archipelago"
        self.backup_dir = self.selaco_dir / f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.auto_build = auto_build
        self.files_created = []
        self.files_patched = []
        
    def log(self, message, level="INFO"):
        prefix = {"INFO": "[+]", "WARN": "[!]", "ERROR": "[X]", "SUCCESS": "[✓]"}
        print(f"{prefix.get(level, '[?]')} {message}")
    
    def create_backup(self, files):
        """Backup files before modification"""
        self.log(f"Creating backup in {self.backup_dir}")
        self.backup_dir.mkdir(exist_ok=True)
        
        for file in files:
            if file.exists():
                rel_path = file.relative_to(self.selaco_dir)
                backup_path = self.backup_dir / rel_path
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file, backup_path)
                self.log(f"Backed up: {rel_path}", "SUCCESS")
    
    def create_archipelago_websocket_h(self):
        """Create archipelago_websocket.h"""
        content = '''// archipelago_websocket.h
// Archipelago WebSocket Client for Selaco
// Based on libwebsockets with single-threaded architecture

#pragma once

#include <libwebsockets.h>
#include <string>
#include <queue>
#include <mutex>
#include <functional>
#include <memory>
#include <atomic>
#include <nlohmann/json.hpp>

namespace Archipelago {

using json = nlohmann::json;

// Forward declarations
class WebSocketClient;

// Session data for libwebsockets callback
struct SessionData {
    WebSocketClient* client;
    bool established;
    std::vector<uint8_t> rx_buffer;
    size_t rx_offset;
    static constexpr size_t RX_BUFFER_SIZE = 65536; // 64KB buffer
};

// Connection state
enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    AUTHENTICATING,
    AUTHENTICATED,
    DISCONNECTING,
    ERROR_STATE
};

// Callback types
using ConnectedCallback = std::function<void()>;
using DisconnectedCallback = std::function<void(int code, const std::string& reason)>;
using MessageCallback = std::function<void(const json& message)>;
using ErrorCallback = std::function<void(const std::string& error)>;

class WebSocketClient {
public:
    WebSocketClient();
    ~WebSocketClient();

    // Connection management
    bool Connect(const std::string& host, int port = 38281, bool use_ssl = true);
    void Disconnect();
    bool IsConnected() const { return state_ == ConnectionState::CONNECTED || 
                                     state_ == ConnectionState::AUTHENTICATING || 
                                     state_ == ConnectionState::AUTHENTICATED; }
    ConnectionState GetState() const { return state_; }
    
    // Message handling
    bool SendJSON(const json& message);
    bool SendRaw(const uint8_t* data, size_t length);
    
    // Service the websocket (call from game loop)
    void Service();
    
    // Callbacks
    void SetConnectedCallback(ConnectedCallback cb) { on_connected_ = cb; }
    void SetDisconnectedCallback(DisconnectedCallback cb) { on_disconnected_ = cb; }
    void SetMessageCallback(MessageCallback cb) { on_message_ = cb; }
    void SetErrorCallback(ErrorCallback cb) { on_error_ = cb; }
    
    // Get connection info
    std::string GetConnectionString() const;
    
    // Static callback for libwebsockets
    static int LwsCallback(struct lws* wsi, enum lws_callback_reasons reason,
                          void* user, void* in, size_t len);

private:
    // Internal methods
    void ProcessIncomingData(const uint8_t* data, size_t length);
    void CleanupConnection();
    bool CreateContext(bool use_ssl);
    void DestroyContext();
    void SetState(ConnectionState new_state);
    void HandleError(const std::string& error);
    bool FlushSendQueue();
    
    // LibWebSockets members
    struct lws_context* context_;
    struct lws* wsi_;
    SessionData session_data_;
    
    // Connection info
    std::string host_;
    int port_;
    bool use_ssl_;
    std::atomic<ConnectionState> state_;
    
    // Message queues
    mutable std::mutex send_mutex_;
    std::queue<std::vector<uint8_t>> send_queue_;
    size_t total_send_queue_size_;
    static constexpr size_t MAX_SEND_QUEUE_SIZE = 1024 * 1024; // 1MB max queue
    
    // Callbacks
    ConnectedCallback on_connected_;
    DisconnectedCallback on_disconnected_;
    MessageCallback on_message_;
    ErrorCallback on_error_;
    
    // Timing
    uint64_t last_ping_time_;
    uint64_t last_pong_time_;
    static constexpr uint64_t PING_INTERVAL_MS = 30000; // 30 seconds
    static constexpr uint64_t PING_TIMEOUT_MS = 60000;  // 60 seconds
    
    // JSON parsing buffer
    std::string json_accumulator_;
};

} // namespace Archipelago
'''
        file_path = self.archipelago_dir / "archipelago_websocket.h"
        file_path.write_text(content)
        self.files_created.append(file_path)
        self.log(f"Created: {file_path.relative_to(self.selaco_dir)}", "SUCCESS")
    
    def create_archipelago_websocket_cpp(self):
        """Create archipelago_websocket.cpp"""
        content = '''// archipelago_websocket.cpp
// Implementation of Archipelago WebSocket Client

#include "archipelago_websocket.h"
#include <chrono>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace Archipelago {

// Logging helpers
#define AP_LOG_ERROR(fmt, ...) printf("[AP-ERROR] " fmt "\\n", ##__VA_ARGS__)
#define AP_LOG_INFO(fmt, ...) printf("[AP-INFO] " fmt "\\n", ##__VA_ARGS__)
#define AP_LOG_DEBUG(fmt, ...) // printf("[AP-DEBUG] " fmt "\\n", ##__VA_ARGS__)

// Helper to get current time in milliseconds
static uint64_t GetTimeMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

WebSocketClient::WebSocketClient() 
    : context_(nullptr)
    , wsi_(nullptr)
    , session_data_{}
    , port_(38281)
    , use_ssl_(true)
    , state_(ConnectionState::DISCONNECTED)
    , total_send_queue_size_(0)
    , last_ping_time_(0)
    , last_pong_time_(0) {
    
    session_data_.client = this;
    session_data_.rx_buffer.resize(SessionData::RX_BUFFER_SIZE);
}

WebSocketClient::~WebSocketClient() {
    Disconnect();
}

bool WebSocketClient::Connect(const std::string& host, int port, bool use_ssl) {
    if (state_ != ConnectionState::DISCONNECTED) {
        HandleError("Already connected or connecting");
        return false;
    }
    
    host_ = host;
    port_ = port;
    use_ssl_ = use_ssl;
    
    // Create LWS context
    if (!CreateContext(use_ssl)) {
        return false;
    }
    
    // Build connection address
    std::string protocol = use_ssl ? "wss" : "ws";
    std::string address = "/" ; // Archipelago uses root path
    
    // Setup connection info
    struct lws_client_connect_info ccinfo = {};
    ccinfo.context = context_;
    ccinfo.address = host_.c_str();
    ccinfo.port = port_;
    ccinfo.path = address.c_str();
    ccinfo.host = ccinfo.address;
    ccinfo.origin = ccinfo.address;
    ccinfo.protocol = nullptr; // Let server decide
    ccinfo.ietf_version_or_minus_one = -1; // Latest version
    ccinfo.userdata = &session_data_;
    ccinfo.ssl_connection = use_ssl ? LCCSCF_USE_SSL : 0;
    
    if (use_ssl) {
        // Allow self-signed certificates for development
        ccinfo.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED | 
                                LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
    }
    
    // Attempt connection
    SetState(ConnectionState::CONNECTING);
    wsi_ = lws_client_connect_via_info(&ccinfo);
    
    if (!wsi_) {
        HandleError("Failed to initiate connection");
        CleanupConnection();
        return false;
    }
    
    AP_LOG_INFO("Connecting to %s://%s:%d", protocol.c_str(), host_.c_str(), port_);
    
    // Update timestamps
    last_ping_time_ = last_pong_time_ = GetTimeMs();
    
    return true;
}

void WebSocketClient::Disconnect() {
    if (state_ == ConnectionState::DISCONNECTED) {
        return;
    }
    
    AP_LOG_INFO("Disconnecting from server");
    SetState(ConnectionState::DISCONNECTING);
    
    if (wsi_) {
        // Request graceful close
        lws_callback_on_writable(wsi_);
    }
    
    // Service until disconnected (with timeout)
    auto start_time = GetTimeMs();
    while (state_ != ConnectionState::DISCONNECTED && 
           (GetTimeMs() - start_time) < 5000) { // 5 second timeout
        Service();
#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }
    
    CleanupConnection();
}

bool WebSocketClient::SendJSON(const json& message) {
    if (!IsConnected()) {
        HandleError("Cannot send message - not connected");
        return false;
    }
    
    try {
        std::string data = message.dump();
        return SendRaw(reinterpret_cast<const uint8_t*>(data.c_str()), data.length());
    } catch (const std::exception& e) {
        HandleError(std::string("JSON serialization error: ") + e.what());
        return false;
    }
}

bool WebSocketClient::SendRaw(const uint8_t* data, size_t length) {
    if (!IsConnected()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(send_mutex_);
    
    // Check queue size limit
    if (total_send_queue_size_ + length > MAX_SEND_QUEUE_SIZE) {
        HandleError("Send queue full");
        return false;
    }
    
    // Add to queue with LWS header space
    size_t needed = LWS_PRE + length;
    std::vector<uint8_t> buffer(needed);
    memcpy(&buffer[LWS_PRE], data, length);
    
    send_queue_.push(std::move(buffer));
    total_send_queue_size_ += length;
    
    // Request write callback
    if (wsi_) {
        lws_callback_on_writable(wsi_);
    }
    
    return true;
}

void WebSocketClient::Service() {
    if (!context_) {
        return;
    }
    
    // Service the websocket with 0 timeout (non-blocking)
    lws_service(context_, 0);
    
    // Check for ping timeout
    if (IsConnected()) {
        uint64_t now = GetTimeMs();
        
        // Send ping if needed
        if (now - last_ping_time_ > PING_INTERVAL_MS) {
            uint8_t ping_data[] = { 0x00 };
            lws_write(wsi_, ping_data, 0, LWS_WRITE_PING);
            last_ping_time_ = now;
        }
        
        // Check for timeout
        if (now - last_pong_time_ > PING_TIMEOUT_MS) {
            HandleError("Ping timeout - server not responding");
            Disconnect();
        }
    }
}

std::string WebSocketClient::GetConnectionString() const {
    return (use_ssl_ ? "wss://" : "ws://") + host_ + ":" + std::to_string(port_);
}

// Static callback function
int WebSocketClient::LwsCallback(struct lws* wsi, enum lws_callback_reasons reason,
                                void* user, void* in, size_t len) {
    SessionData* session = static_cast<SessionData*>(user);
    if (!session || !session->client) {
        return 0;
    }
    
    WebSocketClient* client = session->client;
    
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            AP_LOG_INFO("WebSocket connection established");
            session->established = true;
            client->SetState(ConnectionState::CONNECTED);
            client->last_pong_time_ = GetTimeMs();
            
            if (client->on_connected_) {
                client->on_connected_();
            }
            break;
        }
        
        case LWS_CALLBACK_CLIENT_RECEIVE: {
            if (in && len > 0) {
                AP_LOG_DEBUG("Received %zu bytes", len);
                client->ProcessIncomingData(static_cast<const uint8_t*>(in), len);
                client->last_pong_time_ = GetTimeMs();
            }
            break;
        }
        
        case LWS_CALLBACK_CLIENT_RECEIVE_PONG: {
            AP_LOG_DEBUG("Received PONG");
            client->last_pong_time_ = GetTimeMs();
            break;
        }
        
        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            client->FlushSendQueue();
            break;
        }
        
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            std::string error = "Connection error";
            if (in && len > 0) {
                error += ": ";
                error.append(static_cast<const char*>(in), len);
            }
            AP_LOG_ERROR("%s", error.c_str());
            client->HandleError(error);
            client->CleanupConnection();
            break;
        }
        
        case LWS_CALLBACK_CLOSED:
        case LWS_CALLBACK_CLIENT_CLOSED: {
            AP_LOG_INFO("Connection closed");
            int close_code = 1000; // Normal closure
            std::string reason = "Connection closed";
            
            if (client->on_disconnected_) {
                client->on_disconnected_(close_code, reason);
            }
            
            client->CleanupConnection();
            break;
        }
        
        case LWS_CALLBACK_WSI_DESTROY: {
            if (client->wsi_ == wsi) {
                client->wsi_ = nullptr;
            }
            break;
        }
        
        default:
            break;
    }
    
    return 0;
}

void WebSocketClient::ProcessIncomingData(const uint8_t* data, size_t length) {
    // Append to JSON accumulator
    json_accumulator_.append(reinterpret_cast<const char*>(data), length);
    
    // Try to parse complete JSON messages
    // Archipelago sends complete JSON objects/arrays as messages
    try {
        // First check if we have a complete JSON message
        if (!json_accumulator_.empty()) {
            json message = json::parse(json_accumulator_);
            
            // Successfully parsed - process it
            AP_LOG_DEBUG("Parsed JSON message: %s", message.dump().c_str());
            
            if (on_message_) {
                on_message_(message);
            }
            
            // Clear accumulator for next message
            json_accumulator_.clear();
        }
    } catch (const json::parse_error& e) {
        // Not a complete JSON message yet, wait for more data
        // But check for obviously bad data
        if (json_accumulator_.size() > 1024 * 1024) { // 1MB limit
            AP_LOG_ERROR("JSON accumulator too large, clearing");
            json_accumulator_.clear();
        }
    } catch (const std::exception& e) {
        AP_LOG_ERROR("Error processing message: %s", e.what());
        json_accumulator_.clear();
    }
}

void WebSocketClient::CleanupConnection() {
    SetState(ConnectionState::DISCONNECTED);
    
    // Clear the WebSocket instance
    if (wsi_) {
        // Don't call lws_close_reason as it may already be closing
        wsi_ = nullptr;
    }
    
    // Clear queues
    {
        std::lock_guard<std::mutex> lock(send_mutex_);
        std::queue<std::vector<uint8_t>> empty;
        send_queue_.swap(empty);
        total_send_queue_size_ = 0;
    }
    
    // Clear JSON accumulator
    json_accumulator_.clear();
    
    // Destroy context last
    DestroyContext();
}

bool WebSocketClient::CreateContext(bool use_ssl) {
    struct lws_context_creation_info info = {};
    
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN; // Client only
    info.protocols = nullptr; // Use default protocol
    info.gid = -1;
    info.uid = -1;
    info.max_http_header_pool = 16;
    info.fd_limit_per_thread = 1024;
    
    // Set user pointer for callbacks
    info.user = this;
    
    context_ = lws_create_context(&info);
    if (!context_) {
        HandleError("Failed to create libwebsockets context");
        return false;
    }
    
    AP_LOG_DEBUG("Created libwebsockets context");
    return true;
}

void WebSocketClient::DestroyContext() {
    if (context_) {
        lws_context_destroy(context_);
        context_ = nullptr;
        AP_LOG_DEBUG("Destroyed libwebsockets context");
    }
}

void WebSocketClient::SetState(ConnectionState new_state) {
    ConnectionState old_state = state_.exchange(new_state);
    if (old_state != new_state) {
        AP_LOG_DEBUG("State change: %d -> %d", static_cast<int>(old_state), 
                     static_cast<int>(new_state));
    }
}

void WebSocketClient::HandleError(const std::string& error) {
    AP_LOG_ERROR("%s", error.c_str());
    SetState(ConnectionState::ERROR_STATE);
    
    if (on_error_) {
        on_error_(error);
    }
}

bool WebSocketClient::FlushSendQueue() {
    std::lock_guard<std::mutex> lock(send_mutex_);
    
    while (!send_queue_.empty() && wsi_) {
        auto& buffer = send_queue_.front();
        
        // Calculate actual data size (excluding LWS_PRE)
        size_t data_len = buffer.size() - LWS_PRE;
        
        // Write to websocket
        int written = lws_write(wsi_, &buffer[LWS_PRE], data_len, LWS_WRITE_TEXT);
        
        if (written < 0) {
            HandleError("Write failed");
            return false;
        }
        
        if (written < static_cast<int>(data_len)) {
            // Partial write - this shouldn't happen with libwebsockets
            // but handle it just in case
            HandleError("Partial write detected");
            return false;
        }
        
        // Remove from queue
        total_send_queue_size_ -= data_len;
        send_queue_.pop();
        
        // Request more writable callbacks if queue not empty
        if (!send_queue_.empty()) {
            lws_callback_on_writable(wsi_);
        }
    }
    
    return true;
}

} // namespace Archipelago
'''
        file_path = self.archipelago_dir / "archipelago_websocket.cpp"
        file_path.write_text(content)
        self.files_created.append(file_path)
        self.log(f"Created: {file_path.relative_to(self.selaco_dir)}", "SUCCESS")
    
    def create_archipelago_protocol_h(self):
        """Create archipelago_protocol.h"""
        content = '''// archipelago_protocol.h
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
'''
        file_path = self.archipelago_dir / "archipelago_protocol.h"
        file_path.write_text(content)
        self.files_created.append(file_path)
        self.log(f"Created: {file_path.relative_to(self.selaco_dir)}", "SUCCESS")
    
    def create_archipelago_protocol_cpp(self):
        """Create archipelago_protocol.cpp"""
        content = '''// archipelago_protocol.cpp
// Archipelago Protocol Implementation

#include "archipelago_protocol.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace Archipelago {

// Logging helpers (matching websocket implementation)
#define AP_LOG_ERROR(fmt, ...) printf("[AP-ERROR] " fmt "\\n", ##__VA_ARGS__)
#define AP_LOG_INFO(fmt, ...) printf("[AP-INFO] " fmt "\\n", ##__VA_ARGS__)
#define AP_LOG_DEBUG(fmt, ...) // printf("[AP-DEBUG] " fmt "\\n", ##__VA_ARGS__)

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
'''
        file_path = self.archipelago_dir / "archipelago_protocol.cpp"
        file_path.write_text(content)
        self.files_created.append(file_path)
        self.log(f"Created: {file_path.relative_to(self.selaco_dir)}", "SUCCESS")
    
    def create_archipelago_integration_h(self):
        """Create archipelago_integration.h"""
        content = '''// archipelago_integration.h
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
'''
        file_path = self.archipelago_dir / "archipelago_integration.h"
        file_path.write_text(content)
        self.files_created.append(file_path)
        self.log(f"Created: {file_path.relative_to(self.selaco_dir)}", "SUCCESS")
    
    def create_archipelago_integration_cpp(self):
        """Create archipelago_integration.cpp"""
        content = '''// archipelago_integration.cpp
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
'''
        file_path = self.archipelago_dir / "archipelago_integration.cpp"
        file_path.write_text(content)
        self.files_created.append(file_path)
        self.log(f"Created: {file_path.relative_to(self.selaco_dir)}", "SUCCESS")
    
    def create_archipelago_ccmds_cpp(self):
        """Create archipelago_ccmds.cpp"""
        content = '''// archipelago_ccmds.cpp
// Console commands for Archipelago integration

#ifdef ARCHIPELAGO_SUPPORT

#include "c_dispatch.h"
#include "c_console.h"
#include "archipelago/archipelago_integration.h"

CCMD(ap_connect)
{
    if (argv.argc() < 2) {
        Printf("Usage: ap_connect <server> [port]\\n");
        return;
    }
    
    const char* server = argv[1];
    int port = 38281;
    
    if (argv.argc() >= 3) {
        port = atoi(argv[2]);
    }
    
    if (AP_Connect(server, port)) {
        Printf("Connecting to Archipelago server %s:%d...\\n", server, port);
    } else {
        Printf("Failed to connect to Archipelago server\\n");
    }
}

CCMD(ap_disconnect)
{
    AP_Disconnect();
    Printf("Disconnected from Archipelago\\n");
}

CCMD(ap_auth)
{
    if (argv.argc() < 2) {
        Printf("Usage: ap_auth <slot_name> [password]\\n");
        return;
    }
    
    const char* slot = argv[1];
    const char* password = argv.argc() >= 3 ? argv[2] : nullptr;
    
    AP_Authenticate(slot, password);
}

CCMD(ap_status)
{
    if (AP_IsConnected()) {
        Printf("Connected to Archipelago server\\n");
    } else {
        Printf("Not connected to Archipelago\\n");
    }
}

// Register commands on startup
struct ArchipelagoCommandRegistrar {
    ArchipelagoCommandRegistrar() {
        // Commands are automatically registered by CCMD macro
        Printf("Archipelago console commands registered\\n");
    }
};

static ArchipelagoCommandRegistrar registrar;

#endif // ARCHIPELAGO_SUPPORT
'''
        file_path = self.archipelago_dir / "archipelago_ccmds.cpp"
        file_path.write_text(content)
        self.files_created.append(file_path)
        self.log(f"Created: {file_path.relative_to(self.selaco_dir)}", "SUCCESS")
    
    def patch_cmakelists(self):
        """Patch CMakeLists.txt"""
        cmake_file = self.src_dir / "CMakeLists.txt"
        if not cmake_file.exists():
            self.log("src/CMakeLists.txt not found!", "ERROR")
            return False
        
        self.log("Patching CMakeLists.txt...")
        
        with open(cmake_file, 'r') as f:
            content = f.read()
        
        # Check if already patched
        if "ENABLE_ARCHIPELAGO" in content:
            self.log("CMakeLists.txt already contains Archipelago support", "WARN")
            return True
        
        # Find insertion point
        insert_markers = [
            "option(NO_OPENAL",
            "option(FORCE_INTERNAL_ZLIB",
            "option(DYN_OPENAL",
            "endif()"
        ]
        
        insert_marker = None
        for marker in insert_markers:
            if marker in content:
                insert_marker = marker
                break
        
        if not insert_marker:
            self.log("Could not find suitable insertion point in CMakeLists.txt", "ERROR")
            return False
        
        # Insert the archipelago configuration
        archipelago_config = '''
# =============================================================================
# ARCHIPELAGO WEBSOCKET SUPPORT
# =============================================================================

option(ENABLE_ARCHIPELAGO "Enable Archipelago multiworld support" ON)

if(ENABLE_ARCHIPELAGO)
    message(STATUS "Building with Archipelago support")
    
    include(FetchContent)
    
    # libwebsockets
    FetchContent_Declare(
        libwebsockets
        GIT_REPOSITORY https://github.com/warmcat/libwebsockets.git
        GIT_TAG v4.3.3
    )
    
    set(LWS_WITH_SSL ON CACHE BOOL "" FORCE)
    set(LWS_WITHOUT_TESTAPPS ON CACHE BOOL "" FORCE)
    set(LWS_WITHOUT_TEST_SERVER ON CACHE BOOL "" FORCE)
    set(LWS_WITHOUT_TEST_CLIENT ON CACHE BOOL "" FORCE)
    set(LWS_WITH_MINIMAL_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(LWS_WITH_BUNDLED_ZLIB ON CACHE BOOL "" FORCE)
    set(LWS_WITH_HTTP2 OFF CACHE BOOL "" FORCE)
    
    if(WIN32)
        set(LWS_WITH_MBEDTLS OFF CACHE BOOL "" FORCE)
        set(LWS_OPENSSL_SUPPORT ON CACHE BOOL "" FORCE)
    endif()
    
    FetchContent_MakeAvailable(libwebsockets)
    
    # JSON library
    FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
    )
    FetchContent_MakeAvailable(json)
    
    # Add Archipelago sources
    list(APPEND FASTMATH_SOURCES
        archipelago/archipelago_websocket.cpp
        archipelago/archipelago_protocol.cpp
        archipelago/archipelago_integration.cpp
        archipelago/archipelago_ccmds.cpp
    )
    
    add_definitions(-DARCHIPELAGO_SUPPORT)
endif()

'''
        
        # Insert after marker
        marker_pos = content.find(insert_marker)
        line_end = content.find('\n', marker_pos)
        new_content = content[:line_end+1] + archipelago_config + content[line_end+1:]
        
        # Also need to find and patch target_link_libraries
        # Find the main executable target (could be selaco, zdoom, etc.)
        possible_targets = ["zdoom", "selaco", "gzdoom"]
        target_name = None
        
        for target in possible_targets:
            if f"add_executable( {target}" in new_content or f"add_executable({target}" in new_content:
                target_name = target
                break
        
        if not target_name:
            self.log("Could not determine executable target name", "WARN")
            target_name = "zdoom"  # Default guess
        
        # Find target_link_libraries for the main target
        link_pattern = f"target_link_libraries( {target_name}" 
        link_pattern2 = f"target_link_libraries({target_name}"
        
        link_pos = new_content.find(link_pattern)
        if link_pos == -1:
            link_pos = new_content.find(link_pattern2)
        
        if link_pos != -1:
            # Find the closing parenthesis
            paren_count = 1
            pos = new_content.find('(', link_pos) + 1
            while paren_count > 0 and pos < len(new_content):
                if new_content[pos] == '(':
                    paren_count += 1
                elif new_content[pos] == ')':
                    paren_count -= 1
                pos += 1
            
            if paren_count == 0:
                # Insert before closing parenthesis
                insert_pos = pos - 1
                link_addition = f'''
    $<$<BOOL:${{ENABLE_ARCHIPELAGO}}>:websockets>
    $<$<BOOL:${{ENABLE_ARCHIPELAGO}}>:nlohmann_json::nlohmann_json>
    $<$<AND:$<BOOL:${{ENABLE_ARCHIPELAGO}}>,$<PLATFORM_ID:Windows>>:ws2_32>
    $<$<AND:$<BOOL:${{ENABLE_ARCHIPELAGO}}>,$<PLATFORM_ID:Windows>>:iphlpapi>
    $<$<AND:$<BOOL:${{ENABLE_ARCHIPELAGO}}>,$<PLATFORM_ID:Windows>>:crypt32>
'''
                new_content = new_content[:insert_pos] + link_addition + new_content[insert_pos:]
        
        # Write back
        with open(cmake_file, 'w') as f:
            f.write(new_content)
        
        self.files_patched.append(cmake_file)
        self.log("CMakeLists.txt patched successfully", "SUCCESS")
        return True
    
    def patch_main_loop(self):
        """Patch main game loop to add AP_Update call"""
        self.log("Patching main game loop...")
        
        # Possible files containing the main loop
        possible_files = [
            self.src_dir / "d_main.cpp",
            self.src_dir / "g_game.cpp",
            self.src_dir / "d_net.cpp",
        ]
        
        patched = False
        for file in possible_files:
            if file.exists():
                with open(file, 'r') as f:
                    content = f.read()
                
                # Look for main loop functions
                if "D_ProcessEvents" in content or "G_Ticker" in content or "D_DoomLoop" in content:
                    self.log(f"Found game loop in {file.name}")
                    
                    # Add include at the top
                    if '#include' in content and 'archipelago_integration.h' not in content:
                        first_include = content.find('#include')
                        line_end = content.find('\n', first_include)
                        
                        include_line = '\n#ifdef ARCHIPELAGO_SUPPORT\n#include "archipelago/archipelago_integration.h"\n#endif\n'
                        content = content[:line_end+1] + include_line + content[line_end+1:]
                    
                    # Add update call
                    if "AP_Update()" not in content:
                        # Find a good place to add the update
                        markers = ["D_ProcessEvents", "G_Ticker", "NetUpdate", "D_DoomLoop"]
                        for marker in markers:
                            if marker in content:
                                # Find the function containing this marker
                                marker_pos = content.find(marker)
                                
                                # Look for the opening brace of the function
                                brace_pos = content.find('{', marker_pos)
                                if brace_pos != -1:
                                    # Find the end of the first line after the brace
                                    line_end = content.find('\n', brace_pos)
                                    
                                    update_code = '''
#ifdef ARCHIPELAGO_SUPPORT
    // Update Archipelago client
    AP_Update();
#endif
'''
                                    content = content[:line_end+1] + update_code + content[line_end+1:]
                                    break
                    
                    with open(file, 'w') as f:
                        f.write(content)
                    
                    self.files_patched.append(file)
                    self.log(f"Patched {file.name}", "SUCCESS")
                    patched = True
                    break
        
        if not patched:
            self.log("Could not find main game loop to patch", "WARN")
            self.log("You may need to manually add AP_Update() to your game loop", "WARN")
        
        return patched
    
    def create_build_script(self):
        """Create a build script"""
        script_content = '''@echo off
REM build_archipelago.bat - Build Selaco with Archipelago support

echo ========================================
echo Building Selaco with Archipelago Support
echo ========================================
echo.

REM Check if we're in the right directory
if not exist "src\\CMakeLists.txt" (
    echo ERROR: src\\CMakeLists.txt not found!
    echo Please run this script from the Selaco root directory.
    pause
    exit /b 1
)

REM Create build directory
if not exist "build-archipelago" mkdir build-archipelago
cd build-archipelago

REM Configure with CMake
echo Configuring with CMake...
cmake -G "Visual Studio 17 2022" -A x64 ^
    -DENABLE_ARCHIPELAGO=ON ^
    -DCMAKE_BUILD_TYPE=Release ^
    ..\\src

if %errorlevel% neq 0 (
    echo.
    echo ERROR: CMake configuration failed!
    pause
    exit /b 1
)

REM Build
echo.
echo Building Selaco...
cmake --build . --config Release --parallel

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo Build completed successfully!
echo ========================================
echo.
echo Executable location: build-archipelago\\Release\\selaco.exe
echo.
echo To test Archipelago support:
echo 1. Run selaco.exe
echo 2. Open console with ~ key
echo 3. Type: ap_connect archipelago.gg
echo 4. Type: ap_auth YourSlotName
echo.
pause
'''
        
        build_script = self.selaco_dir / "build_archipelago.bat"
        build_script.write_text(script_content)
        self.log(f"Created build script: {build_script.name}", "SUCCESS")
        
        return build_script
    
    def attempt_build(self):
        """Attempt to build the project"""
        self.log("\nAttempting to build Selaco with Archipelago support...")
        
        build_dir = self.selaco_dir / "build-archipelago"
        build_dir.mkdir(exist_ok=True)
        
        # Configure
        self.log("Running CMake configuration...")
        cmake_cmd = [
            "cmake",
            "-G", "Visual Studio 17 2022",
            "-A", "x64",
            "-DENABLE_ARCHIPELAGO=ON",
            "-DCMAKE_BUILD_TYPE=Release",
            str(self.src_dir)
        ]
        
        try:
            result = subprocess.run(cmake_cmd, cwd=build_dir, capture_output=True, text=True)
            if result.returncode != 0:
                self.log("CMake configuration failed!", "ERROR")
                self.log(result.stderr, "ERROR")
                return False
            
            self.log("CMake configuration successful", "SUCCESS")
            
            # Build
            self.log("Building project...")
            build_cmd = ["cmake", "--build", ".", "--config", "Release", "--parallel"]
            
            result = subprocess.run(build_cmd, cwd=build_dir, capture_output=True, text=True)
            if result.returncode != 0:
                self.log("Build failed!", "ERROR")
                self.log(result.stderr, "ERROR")
                return False
            
            self.log("Build completed successfully!", "SUCCESS")
            self.log(f"Executable should be in: {build_dir / 'Release'}", "SUCCESS")
            return True
            
        except FileNotFoundError:
            self.log("CMake not found in PATH", "ERROR")
            self.log("Please install CMake or build manually using build_archipelago.bat", "WARN")
            return False
        except Exception as e:
            self.log(f"Build error: {str(e)}", "ERROR")
            return False
    
    def run(self):
        """Run the complete setup"""
        self.log(f"Setting up Archipelago for Selaco at: {self.selaco_dir}")
        self.log(f"Source files location: {self.src_dir}")
        
        # Verify directory structure
        if not self.src_dir.exists():
            self.log("src directory not found!", "ERROR")
            return False
        
        if not (self.src_dir / "CMakeLists.txt").exists():
            self.log("src/CMakeLists.txt not found!", "ERROR")
            self.log("Are you in the correct Selaco source directory?", "ERROR")
            return False
        
        # Create backup
        files_to_backup = [
            self.src_dir / "CMakeLists.txt",
            self.src_dir / "d_main.cpp",
            self.src_dir / "g_game.cpp",
            self.src_dir / "d_net.cpp",
        ]
        self.create_backup([f for f in files_to_backup if f.exists()])
        
        # Create archipelago directory
        self.log(f"\nCreating archipelago directory at: {self.archipelago_dir}")
        self.archipelago_dir.mkdir(exist_ok=True)
        
        # Create all files
        self.log("\nCreating Archipelago implementation files...")
        self.create_archipelago_websocket_h()
        self.create_archipelago_websocket_cpp()
        self.create_archipelago_protocol_h()
        self.create_archipelago_protocol_cpp()
        self.create_archipelago_integration_h()
        self.create_archipelago_integration_cpp()
        self.create_archipelago_ccmds_cpp()
        
        # Patch existing files
        self.log("\nPatching Selaco source files...")
        self.patch_cmakelists()
        self.patch_main_loop()
        
        # Create build script
        build_script = self.create_build_script()
        
        # Summary
        self.log("\n" + "="*60)
        self.log("SETUP COMPLETE!", "SUCCESS")
        self.log("="*60)
        
        self.log(f"\nFiles created: {len(self.files_created)}")
        for f in self.files_created:
            self.log(f"  - {f.relative_to(self.selaco_dir)}")
        
        self.log(f"\nFiles patched: {len(self.files_patched)}")
        for f in self.files_patched:
            self.log(f"  - {f.relative_to(self.selaco_dir)}")
        
        self.log(f"\nBackup created at: {self.backup_dir}")
        
        # Attempt to build if requested
        if self.auto_build:
            self.attempt_build()
        else:
            self.log("\nTo build Selaco with Archipelago support:")
            self.log(f"  1. Run: {build_script.name}")
            self.log("  OR")
            self.log("  2. Manually build with CMake:")
            self.log("     mkdir build-archipelago")
            self.log("     cd build-archipelago")
            self.log("     cmake ../src -G \"Visual Studio 17 2022\" -A x64 -DENABLE_ARCHIPELAGO=ON")
            self.log("     cmake --build . --config Release")
        
        self.log("\nConsole commands available in-game:")
        self.log("  ap_connect <server> [port]  - Connect to Archipelago server")
        self.log("  ap_auth <slot> [password]   - Authenticate with server")
        self.log("  ap_disconnect               - Disconnect from server")
        self.log("  ap_status                   - Show connection status")
        
        return True

def main():
    parser = argparse.ArgumentParser(
        description="One-click Archipelago setup for Selaco",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup_archipelago_selaco.py C:\\Users\\Skuldier\\Documents\\SelacoFreshSource
  python setup_archipelago_selaco.py . --build
  python setup_archipelago_selaco.py /path/to/selaco
        """
    )
    
    parser.add_argument(
        "selaco_dir",
        help="Path to Selaco source directory (containing src/ folder)"
    )
    
    parser.add_argument(
        "--build", "-b",
        action="store_true",
        help="Automatically build after setup (requires CMake in PATH)"
    )
    
    args = parser.parse_args()
    
    # Run setup
    setup = ArchipelagoSelacoSetup(args.selaco_dir, args.build)
    success = setup.run()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()