// archipelago_websocket.cpp
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
#define AP_LOG_ERROR(fmt, ...) printf("[AP-ERROR] " fmt "\n", ##__VA_ARGS__)
#define AP_LOG_INFO(fmt, ...) printf("[AP-INFO] " fmt "\n", ##__VA_ARGS__)
#define AP_LOG_DEBUG(fmt, ...) // printf("[AP-DEBUG] " fmt "\n", ##__VA_ARGS__)

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
