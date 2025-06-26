// archipelago_websocket.h
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
