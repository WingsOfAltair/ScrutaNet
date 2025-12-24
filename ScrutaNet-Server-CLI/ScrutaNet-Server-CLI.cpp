#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/filesystem.hpp>
#include <boost/regex.hpp>
#include <boost/locale.hpp>
#include <boost/process.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <atomic>
#include <chrono>
#include <boost/algorithm/string/trim.hpp>        
#include "../shared/AsyncLogger.h" 
#include "../shared/AsyncStorageLogger.h" 

AsyncLogger logger("server.log");
AsyncStorageLogger cracked("cracked.txt");

using boost::asio::ip::tcp;

int SERVER_PORT = 0;
std::unordered_map<std::string, std::shared_ptr<tcp::socket>> clients;
std::unordered_map<std::string, bool> clients_ready;
std::unordered_set<std::string> task_participants;         // clients currently assigned this task (includes catch-ups)
std::mutex clients_mutex;  // Protect shared containers
std::atomic<bool> match_found(false);
std::atomic<bool> task_active(false); // indicates a task is currently active
std::atomic<int> current_task_id(0);  // simple task id counter
int total_clients = 0;

std::string hash_type;
std::string hash;
std::string salt;
std::string password;

std::vector<std::tuple<std::string, std::string, std::string>> cracked_hashes_storage;

auto start = std::chrono::high_resolution_clock::now();
auto end = std::chrono::high_resolution_clock::now();

// Read pre-cracked hash storage
void readHashStorage(const std::string& filename) {
    boost::filesystem::path fullPath = boost::filesystem::absolute(filename);
    std::ifstream configFile(fullPath.string());

    if (boost::filesystem::exists(fullPath)) {
        std::string line;
        while (std::getline(configFile, line)) {
            std::istringstream iss(line);

            if (std::getline(iss, hash, ':') &&
                std::getline(iss, salt, ':') &&
                std::getline(iss, password)) {
                cracked_hashes_storage.emplace_back(hash, salt, password);
            }
            else {
                std::cerr << "Invalid line format in cracked.txt: " << line << std::endl;
            }
        }
        configFile.close();
    }
    else {
        std::cerr << "Pre-cracked Hash storage does not exist.\n";
    }
}

// Read config file
std::map<std::string, std::string> readConfig(const std::string& filename) {
    std::map<std::string, std::string> configMap;
    boost::filesystem::path fullPath = boost::filesystem::absolute(filename);
    std::ifstream configFile(fullPath.string());

    if (boost::filesystem::exists(fullPath)) {
        std::string line;
        while (std::getline(configFile, line)) {
            size_t delimiterPos = line.find('=');
            if (delimiterPos != std::string::npos) {
                std::string key = line.substr(0, delimiterPos);
                std::string value = line.substr(delimiterPos + 1);
                configMap[key] = value;
            }
        }
        configFile.close();
    }
    else {
        std::cerr << "Config file does not exist.\n";
    }

    return configMap;
}

std::string extract_password_from_match_response(const std::string& match_info) {
    std::istringstream iss(match_info);
    std::string word;
    int count = 0;

    while (iss >> word) {
        count++;
        if (count == 1) {
            return word;
        }
    }
    return "";
}

// Convert to lowercase
std::string to_lowercase(const std::string& str) {
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return lower_str;
}

bool is_valid_hashtype(const std::string& hash_type) {
    static const std::vector<std::string> valid_types = {
        "bcrypt", "scrypt", "argon2",
        "md5", "sha1", "sha256", "sha384", "sha512",
        "sha3-224", "sha3-256", "sha3-384", "sha3-512"
    };

    std::string lower_hash_type = to_lowercase(hash_type);

    return std::find(valid_types.begin(), valid_types.end(), lower_hash_type) != valid_types.end();
}

bool isPhpScryptHash(const std::string& hash) {
    boost::regex scryptPattern(R"(^\d+\$\d+\$\d+\$[A-Za-z0-9./]+\$[A-Za-z0-9./+=]+$)");
    return boost::regex_match(hash, scryptPattern);
}

// Check bcrypt hash format
bool isBcryptHash(const std::string& hash) {
    boost::regex bcryptPattern(R"(^\$(2[aby])\$\d{2}\$[./A-Za-z0-9]{53}$)");
    return boost::regex_match(hash, bcryptPattern);
}

// Determine hash type by length
std::string getHashType(const std::string& hash) {
    if (hash.rfind("$argon2id$", 0) == 0) return "Argon2id";
    if (hash.rfind("$argon2i$", 0) == 0) return "Argon2i";
    if (hash.rfind("$argon2d$", 0) == 0) return "Argon2d";

    std::map<std::string, size_t> hashTypes = {
        {"MD5", 32}, {"SHA-1 or RIPEMD-160", 40}, {"SHA-224 or SHA3-224", 56},
        {"SHA-256 or SHA3-256", 64}, {"SHA-384 or SHA3-384", 96}, {"SHA-512 or SHA3-512", 128} };
    size_t hashLength = hash.length();
    for (const auto& [type, length] : hashTypes) {
        if (hashLength == length) return type;
    }
    return "Unknown hash type";
}

// Task participant helpers (all protected by clients_mutex internally)
void add_task_participant_locked(const std::string& client_key) {
    task_participants.insert(client_key);
}

void remove_task_participant_locked_and_mark_response(const std::string& client_key) {
    // Called under clients_mutex
    if (task_participants.erase(client_key)) {
        // If participant removed due to an actual response (NO_MATCH/Ready), and no participants remain,
        // that means all assigned clients finished the task => end task.
        if (task_participants.empty()) {
            task_active.store(false, std::memory_order_relaxed);
        }
    }
}

void remove_task_participant_locked_no_response(const std::string& client_key) {
    // remove participant without treating as a response (used previously on disconnect) -- left for completeness.
    task_participants.erase(client_key);
    // Do NOT set task_active=false here: disconnects should NOT end the task.
}

// Helper: send the current active task to a single client socket and add them as participant on success
void send_current_task_to_client(const std::shared_ptr<tcp::socket>& sock, const std::string& client_key) {
    if (!sock || !sock->is_open()) return;

    std::string message;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        if (hash_type.empty() || hash.empty()) return;
        // Keep same message format clients already expect
        message = hash_type + ":" + hash;
        if (!salt.empty()) {
            message += ":" + salt;
        }
        message += "\n";
    }

    try {
        boost::asio::write(*sock, boost::asio::buffer(message));
        // On successful send, register as participant
        std::lock_guard<std::mutex> lock(clients_mutex);
        add_task_participant_locked(client_key);
    }
    catch (const boost::system::system_error& e) {
        std::cerr << "Failed to send active task to new client: " << e.what() << "\n";
    }
}

// Notify clients with new hash
void notify_clients(
    const std::string& hash_type_param,
    const std::string& hash_param,
    const std::string& salt_param = "")
{
    // store shared task state under lock
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        hash_type = hash_type_param;
        hash = hash_param;
        salt = salt_param;
        task_active = true;
        ++current_task_id;
        // clear any previous participants
        task_participants.clear();
    }

    std::string message = hash_type + ":" + hash;
    if (!salt.empty()) {
        message += ":" + salt;
    }
    message += "\n";

    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto& [client_id, is_ready] : clients_ready) {
        if (is_ready) {
            auto it = clients.find(client_id);
            if (it != clients.end() && it->second && it->second->is_open()) {
                try {
                    boost::asio::write(*it->second, boost::asio::buffer(message));
                    // register as participant only after successful send
                    add_task_participant_locked(client_id);
                }
                catch (const boost::system::system_error& e) {
                    // Optional: handle disconnect or remove client here
                    std::cerr << "Failed to notify client " << client_id << ": " << e.what() << "\n";
                }
            }
        }
    }

    // Mark all clients as not-ready (they're now working)
    for (auto& pair : clients_ready) {
        pair.second = false;
    }
}

// Notify ready clients to reload wordlist/mutation options
void reload_ready_clients() {
    std::string message = "reload\n";

    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto& [client_id, is_ready] : clients_ready) {
        if (is_ready) {
            auto it = clients.find(client_id);
            if (it != clients.end() && it->second && it->second->is_open()) {
                try {
                    boost::asio::write(*it->second, boost::asio::buffer(message));
                }
                catch (const boost::system::system_error& e) {
                    std::cerr << "Failed to send reload to client " << client_id << ": " << e.what() << "\n";
                }
            }
        }
    }

    for (auto& pair : clients_ready) {
        pair.second = false;
    }
}

// Handle each client connection
void handle_client(std::shared_ptr<tcp::socket> client_socket) {
    std::string client_key = client_socket->remote_endpoint().address().to_string() + ":" +
        std::to_string(client_socket->remote_endpoint().port());

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients[client_key] = client_socket;
        clients_ready[client_key] = false;
        std::cout << "Client " << client_key << " has connected.\n";
        ++total_clients;
    }

    // If a task is currently active, send the current task to the newly connected client
    if (task_active && !match_found) {
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            std::cout << "Sending current active task to new client " << client_key << " so it can catch up.\n";
        }
        send_current_task_to_client(client_socket, client_key);
        // client remains not-ready until it responds (client should send Ready or NO_MATCH)
    }

    try {
        boost::asio::streambuf buffer;
        while (true) {
            boost::system::error_code error;
            size_t len = boost::asio::read_until(*client_socket, buffer, "\n", error);

            if (error == boost::asio::error::eof) {
                std::cout << "Client " << client_key << " disconnected normally.\n";
                break;
            }
            else if (error) {
                std::cerr << "Client " << client_key << " read error: " << error.message() << std::endl;
                break;
            }

            std::istream is(&buffer);
            std::string message;
            std::getline(is, message);
            boost::algorithm::trim(message);

            // Handle client messages
            if (message.find("MATCH:") == 0) {
                auto end = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double, std::milli> duration_ms = end - start;

                std::string match_info = message.substr(6); // Remove "MATCH:"
                std::cout << "Client " << client_key << " Match found: " << match_info << std::endl
                    << "Elapsed time: " << duration_ms.count() << " ms" << std::endl;
                match_found = true;
                password = extract_password_from_match_response(match_info);
                bool found = false;
                for (const auto& pair : cracked_hashes_storage) {
                    if (std::get<0>(pair) == hash && std::get<1>(pair) == salt) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    cracked_hashes_storage.emplace_back(hash, salt, password);
                    cracked.log(hash + ":" + salt + ":" + password);
                }
                logger.log(match_info + " by Client " + client_key + ".");
                {
                    std::lock_guard<std::mutex> lock(clients_mutex);
                    for (const auto& [cid, client] : clients) {
                        if (client && client->is_open()) {
                            try {
                                boost::asio::write(*client, boost::asio::buffer("STOP\n"));
                            }
                            catch (const boost::system::system_error& e) {
                                std::cerr << "Failed to send STOP to client: " << e.what() << std::endl;
                            }
                        }
                    }
                    // Task ended
                    task_active = false;
                    // clear participants since STOP was sent
                    task_participants.clear();
                }
            }
            else if (message.find("NO_MATCH") == 0) {
                std::cout << "Match not found in client: " << client_key << std::endl;
                std::lock_guard<std::mutex> lock(clients_mutex);
                // mark client ready
                clients_ready[client_key] = true;
                // if this client was participating, mark response and remove from participants
                remove_task_participant_locked_and_mark_response(client_key);
            }
            else if (message.find("Ready") == 0) {
                std::lock_guard<std::mutex> lock(clients_mutex);
                clients_ready[client_key] = true;
                std::cout << "Client " << client_key << " is ready.\n";
                // If this client was participating, mark response and remove from participants
                remove_task_participant_locked_and_mark_response(client_key);
            }
            // Note: don't treat disconnection as a response; disconnect simply leaves participant entry intact
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception in client handling: " << e.what() << std::endl;
    }

    // Cleanup client on disconnect with lock
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        // IMPORTANT CHANGE:
        // Do NOT remove the client from task_participants on disconnect.
        // Removing participants on disconnect previously allowed the server to consider a task finished
        // when the last assigned client disconnected. We must keep the task active and continue sending
        // catch-up assignments to newly connected clients until an explicit STOP (MATCH) or until
        // assigned participants report NO_MATCH/Ready and the participant set becomes empty.
        //
        // HOWEVER: when the last connected client disconnects (clients map becomes empty), we should
        // terminate the active task and stop sending catch-up messages.
        clients.erase(client_key);
        clients_ready.erase(client_key);
        --total_clients;

        if (clients.empty() && task_active.load(std::memory_order_relaxed)) {
            // last disconnected client event
            std::cout << "No remaining clients connected, Terminating...\n";
            logger.log("No remaining clients connected, Terminating current task.");
            task_active.store(false, std::memory_order_relaxed);
            task_participants.clear();
        }
    }
}

void run_udp_echo_server(unsigned short port) {
    boost::asio::io_context io_service;

    // Create UDP socket bound to given port
    boost::asio::ip::udp::socket socket(
        io_service,
        boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port)
    );

    char data[128];  // buffer for incoming data
    boost::asio::ip::udp::endpoint sender_endpoint;

    std::cout << "Ping echo server is listening on port " << port << " UDP..." << std::endl;

    while (true) {
        boost::system::error_code ec;

        // Receive a packet
        std::size_t length = socket.receive_from(
            boost::asio::buffer(data), sender_endpoint, 0, ec
        );

        if (ec && ec != boost::asio::error::message_size) {
            std::cerr << "Receive error: " << ec.message() << std::endl;
            continue;
        }

        std::cout << "Received: " << std::string(data, length)
            << " from " << sender_endpoint.address().to_string() << ":" << sender_endpoint.port() << std::endl;

        // Send response
        std::string response = "pong";
        socket.send_to(boost::asio::buffer(response), sender_endpoint, 0, ec);
        if (ec) {
            std::cerr << "Send error: " << ec.message() << std::endl;
        }
    }
}

// Main function to initialize server and manage client connections
int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    std::locale::global(boost::locale::generator().generate("en_US.UTF-8"));
    std::wcin.imbue(std::locale());
    std::wcout.imbue(std::locale());

    auto config = readConfig("server.ini");
    SERVER_PORT = std::stoi(config["SERVER_PORT"]);

    std::cout << "Reading pre-cracked hashes storage...\n";
    readHashStorage("cracked.txt");

    std::vector<boost::thread> threads;
    threads.emplace_back(run_udp_echo_server, SERVER_PORT);

    boost::asio::io_context io_context;
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), SERVER_PORT));

    std::cout << "Server is listening on port " << SERVER_PORT << " TCP\n";

    // Thread to accept clients
    boost::thread client_handler([&]() {
        while (true) {
            auto client_socket = std::make_shared<tcp::socket>(io_context);
            acceptor.accept(*client_socket);
            boost::thread(handle_client, client_socket).detach();
        }
        });

    // Main loop for hash input
    while (true) {
        while (clients_ready.size() > 0 && std::all_of(clients_ready.begin(), clients_ready.end(), [](auto& entry) { return entry.second; }) && clients_ready.size() > 0) {
            std::cout << "Hash type (BCRYPT, Scrypt, argon2, MD5, SHA1, SHA512, sha384, SHA256, sha224, sha3-512, sha3-384, sha3-256, sha3-224, ripemd160): " << std::endl;
            std::cout << "To check hash type, enter 'type' as the hash type." << std::endl;
            std::cout << "To check connected clients, enter 'connections'." << std::endl;
            std::cout << "To reload connected clients' settings (wordlist/mutation options), enter 'reload'." << std::endl;
            std::cout << "Enter the hash type: ";
            std::getline(std::cin, hash_type);

            if (to_lowercase(hash_type) == "type") {
                std::cout << "Enter the hash: ";
                std::getline(std::cin, hash);

                std::string hashType = getHashType(hash);
                if (hashType == "Unknown hash type") {
                    bool isBcrypt = isBcryptHash(hash);
                    bool isScrypt = isPhpScryptHash(hash);
                    if (isBcrypt) {
                        std::cout << "Hash Type: BCrypt" << std::endl;
                        continue;
                    }
                    else if (isScrypt) {
                        std::cout << "Hash Type: Scrypt" << std::endl;
                        continue;
                    }
                    else {
                        std::cout << "Unknown hash type." << std::endl;
                        continue;
                    }
                }
                else {
                    std::cout << "Hash Type: " << getHashType(hash) << std::endl;
                    continue;
                }
            }

            if (to_lowercase(hash_type) == "connections") {
                std::cout << "Connected clients (" << total_clients << "):\n";
                if (clients_ready.size() < total_clients)
                {
                    std::cout << "There are client(s) connected but still getting ready." << std::endl;
                }
                for (const auto& entry : clients_ready) {
                    std::cout << " - " << entry.first << (entry.second ? " [Ready]" : " [Not Ready]") << "\n";
                }
                continue;
            }

            if (to_lowercase(hash_type) == "reload") {
                reload_ready_clients();
                continue;
            }

            if (!is_valid_hashtype(hash_type)) {
                std::cout << "Unknown hash type." << std::endl;
                continue;
            }

            if (!is_valid_hashtype(hash_type)) {
                std::cout << "Unknown hash type." << std::endl;
                continue;
            }

            std::cout << "Enter the hash: ";
            std::getline(std::cin, hash);

            std::cout << "Enter the salt (leave empty if none, or BCRYPT or argon2): ";
            std::getline(std::cin, salt);

            bool found = false;
            for (const auto& pair : cracked_hashes_storage) {
                if (std::get<0>(pair) == hash && std::get<1>(pair) == salt) {
                    std::cout << "Found pre-cracked Hash: " << std::get<0>(pair) << " Salt: " << std::get<1>(pair) << " Decoded: " << std::get<2>(pair) << std::endl;
                    logger.log("Found pre-cracked Hash: " + std::get<0>(pair) + " Salt: " + std::get<1>(pair) + " Decoded: " + std::get<2>(pair));
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (clients_ready.size() == 0)
                {
                    std::cout << "There are no ready clients. Forfieting request." << std::endl;
                    match_found = false;
                    continue;
                }

                bool allReady = std::all_of(clients_ready.begin(), clients_ready.end(),
                    [](const auto& pair) {
                        return pair.second; // second = is_ready
                    });

                if (!allReady)
                {
                    std::cout << "All connected clients must be ready." << std::endl;
                    continue;
                }

                if (!hash_type.empty() && !hash.empty()) {
                    start = std::chrono::high_resolution_clock::now();
                    notify_clients(hash_type, hash, salt);
                    match_found = false;

                    for (auto& pair : clients_ready) {
                        pair.second = false;
                    }

                    std::cout << "Processing entered hash, please wait...\n";

                    // Wait until the task is cleared (by MATCH -> STOP or by all participants responding via NO_MATCH/Ready).
                    // Do NOT consider client disconnects as participant responses (disconnects won't stop catch-up behavior),
                    // except when the last connected client has disconnected (handled in disconnect cleanup above).
                    while (task_active.load(std::memory_order_relaxed) && !match_found.load(std::memory_order_relaxed)) {
                        boost::this_thread::sleep_for(boost::chrono::milliseconds(100));
                    }

                    if (!match_found) {
                        auto end_local = std::chrono::high_resolution_clock::now();
                        std::chrono::duration<double, std::milli> duration_ms = end_local - start;
                        std::cout << "No matches found, please wait until you can enter a new hash...\n";
                        std::cout << "Elapsed time: " << duration_ms.count() << " ms\n";
                    }
                    else {
                        std::cout << "Match found, please wait until you can enter a new hash...\nThis may take a while depending on your clients' hardware/os.\n";
                    }
                }
                else {
                    std::cout << "No hash entered. Try again.\n";
                }
            }
        }
    }

    client_handler.join();
    return 0;
}