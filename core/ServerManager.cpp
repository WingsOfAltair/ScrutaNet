#include "ServerManager.h"
#include <boost/algorithm/string/trim.hpp>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

ServerManager::ServerManager(QObject* parent)
    : QObject(parent),
    serverLogger("server.log"),
    crackedLogger("cracked.log")
{
    readCrackedHashes("cracked.txt");

    std::ifstream in("server.ini");
    int port = 5000;
    if (in.is_open()) {
        std::string line;
        while (std::getline(in, line)) {
            auto pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);
                if (key == "SERVER_PORT") port = std::stoi(value);
            }
        }
    }

    startServer(port);
}

ServerManager::~ServerManager() {
    stopServer();
}

void ServerManager::shutdownClient(const std::string& clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end() && it->second && it->second->is_open())
        boost::asio::write(*it->second, boost::asio::buffer("SHUTDOWN\n"));
}

void ServerManager::restartClient(const std::string& clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end() && it->second && it->second->is_open())
        boost::asio::write(*it->second, boost::asio::buffer("RESTART\n"));
}

void ServerManager::setClientNickname(const std::string& clientId, const std::string& newNickname) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clientsReady.find(clientId);
    if (it != clientsReady.end()) it->second.first = newNickname;
    else clientsReady[clientId] = {newNickname,false};
}

void ServerManager::logServer(const std::string& message) {
    serverLogger.log(message);
}

void ServerManager::asyncAcceptClient() {
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(*ioContext);

    acceptor->async_accept(*socket, [this, socket](const boost::system::error_code& ec) {
        if (!serverRunning || ec == boost::asio::error::operation_aborted) return;
        if (!ec) std::thread(&ServerManager::handleClient, this, socket).detach();
        else {
            emit logMessage("Accept error: " + QString::fromStdString(ec.message()));
            logServer(std::string("Accept error: ") + ec.message());
        }
        asyncAcceptClient();
    });
}

void ServerManager::StopCrackingClients() {
    // Run notifyStopAll in a worker thread to avoid blocking GUI
    std::thread([this]() {
        this->notifyStopAll();  // safely sends STOP to all clients

        // After sending STOP, mark clients idle and update UI
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            currentHashMessage.clear();
            for (auto& [id, state] : clientsReady) {
                state.second = false; // mark idle
            }
        }

        emit clientsStatusChanged();
    }).detach();
}

// ------------------- UDP Echo ----------------------
void ServerManager::udpEchoServer() {
    // Already initialized in startServer()
    if (!udpSocket || !udpSocket->is_open()) {
        emit logMessage("UDP socket is not open.");
        return;
    }

    char data[128];  // buffer for incoming data
    boost::asio::ip::udp::endpoint sender_endpoint;

    std::cout << "Ping echo server is listening on port " << serverPort << " UDP..." << std::endl;

    while (serverRunning) {
        boost::system::error_code ec;

        std::size_t length = udpSocket->receive_from(
            boost::asio::buffer(data), sender_endpoint, 0, ec
            );

        if (ec && ec != boost::asio::error::message_size) {
            emit logMessage("Receive error: " + QString::fromStdString(ec.message()));
            logServer(std::string("Receive error: ") + ec.message());
            continue;
        }

        QString msg = "Received: " +
                      QString::fromStdString(std::string(data, length)) +
                      " from " +
                      QString::fromStdString(sender_endpoint.address().to_string()) +
                      ":" +
                      QString::number(sender_endpoint.port());
        emit logMessage(msg);

        logServer(msg.toStdString());

        // Send response
        std::string response = "pong";
        udpSocket->send_to(boost::asio::buffer(response), sender_endpoint, 0, ec);
        if (ec) {
            emit logMessage("Send error: " + QString::fromStdString(ec.message()));
        }
    }
}

// ------------------- Server Start/Stop ----------------------
void ServerManager::startServer(int port) {
    if (serverRunning) return;
    serverRunning = true;
    serverPort = port;

    ioContext = std::make_unique<boost::asio::io_context>();
    workGuard.emplace(boost::asio::make_work_guard(*ioContext));

    acceptor = std::make_unique<boost::asio::ip::tcp::acceptor>(
        *ioContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port));

    udpSocket = std::make_unique<boost::asio::ip::udp::socket>(
        *ioContext, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port));

    std::thread([this]() {
        udpEchoServer();
    }).detach();

    std::thread([this]() {
        asyncAcceptClient();
    }).detach();

    serverThreads.emplace_back([this]() {
        try {
            ioContext->run();  // 🧵 Blocking run loop
        } catch (const std::exception& ex) {
            emit logMessage("io_context exception: " + QString::fromStdString(ex.what()));
            logServer(std::string("io_context exception: ") + ex.what());
        }
    });

    emit logMessage("Server started on port " + QString::number(port));
    logServer("Server started on port " + std::to_string(port));
}

void ServerManager::stopServer() {
    if (!serverRunning) return;
    serverRunning = false;

    if (acceptor && acceptor->is_open()) { boost::system::error_code ec; acceptor->cancel(ec); acceptor->close(ec); }
    if (udpSocket && udpSocket->is_open()) { boost::system::error_code ec; udpSocket->cancel(ec); udpSocket->close(ec); }
    if (workGuard.has_value()) workGuard.reset();
    if (ioContext) ioContext->stop();

    for (auto& t : serverThreads)
        if (t.joinable()) t.join();

    serverThreads.clear();

    clients.clear();
    clientsReady.clear();
    totalClients = 0;
    currentHashMessage.clear();

    emit logMessage("Server stopped.");
    serverLogger.log("Server stopped.");
}

void ServerManager::handleClient(std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
    std::string clientId = socket->remote_endpoint().address().to_string() + ":" +
                           std::to_string(socket->remote_endpoint().port());

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients[clientId] = socket;

        // Determine initial state: Working if there's an active task, Ready if idle
        bool isWorking = !currentHashMessage.empty() && !matchFound;
        clientsReady[clientId] = {"", isWorking};

        emit clientReadyStateChanged(QString::fromStdString(clientId), !isWorking); // Ready = !Working
        emit clientsStatusChanged();
    }

    emit logMessage("Client " + QString::fromStdString(clientId) + " has connected.");
    emit clientConnected(QString::fromStdString(clientId));

    // Send catch-up if task is active
    if (!currentHashMessage.empty() && !matchFound) {
        std::thread(&ServerManager::sendCatchup, this, socket, clientId).detach();
    }

    try {
        boost::asio::streambuf buffer;
        while (serverRunning && socket->is_open()) {
            boost::asio::read_until(*socket, buffer, "\n");
            std::istream is(&buffer);
            std::string message;
            std::getline(is, message);
            boost::algorithm::trim(message);

            std::lock_guard<std::mutex> lock(clientsMutex);

            if (message.find("Ready") == 0 || message.find("NO_MATCH") == 0) {
                auto it = clientsReady.find(clientId);
                std::string nickname = (it != clientsReady.end()) ? it->second.first : "";
                if (it != clientsReady.end()) {
                    it->second.second = false; // Ready
                    emit clientReadyStateChanged(QString::fromStdString(clientId), true);
                    emit clientsStatusChanged();
                }

                // Only emit StopCrackingNotStop if no clients are working and no match found
                bool allIdle = std::all_of(clientsReady.begin(), clientsReady.end(),
                                           [](const auto& p) { return !p.second.second; });

                if (allIdle && !matchFound) {
                    emit StopCrackingNotStop();
                    auto end = std::chrono::high_resolution_clock::now();
                    std::chrono::duration<double, std::milli> duration_ms = end - start;

                    emit logMessage("Match was not found"
                                    " by Client " + QString::fromStdString(clientId) + " " + QString::fromStdString(nickname) +
                                    " Elapsed time: " + QString::number(duration_ms.count(), 'f', 3) + " ms.");
                } else if (allIdle) {
                    emit StopCrackingNotStop();
                }
            }
            else if (message.find("MATCH:") == 0) {
                matchFound = true;
                currentPassword = QString::fromStdString(message.substr(6)).split(' ').first();

                // Save cracked hash if not already saved
                {
                    bool alreadySaved = std::any_of(crackedHashes.begin(), crackedHashes.end(),
                                                    [this](const auto& t){ return std::get<0>(t) == currentHash && std::get<1>(t) == currentSalt; });
                    if (!alreadySaved) {
                        crackedHashes.emplace_back(currentHash, currentSalt, currentPassword);
                        crackedLogger.log(currentHash.toStdString() + ":" + currentSalt.toStdString() + ":" + currentPassword.toStdString());

                        // Log match only for the client that found it
                        auto end = std::chrono::high_resolution_clock::now();
                        std::chrono::duration<double, std::milli> duration_ms = end - start;
                        std::string match_info = message.substr(6);

                        // Get nickname if available
                        auto it = clientsReady.find(clientId);
                        std::string nickname = (it != clientsReady.end()) ? it->second.first : "";

                        logServer("Match: " + match_info + " by Client " + clientId +
                                  (nickname.empty() ? "" : " (" + nickname + ")") +
                                  " Elapsed time: " + std::to_string(duration_ms.count()) + " ms.");
                        emit logMessage("Match: " + QString::fromStdString(match_info) +
                                        " by Client " + QString::fromStdString(clientId) +
                                        (nickname.empty() ? "" : " (" + QString::fromStdString(nickname) + ")") +
                                        " Elapsed time: " + QString::number(duration_ms.count(), 'f', 3) + " ms.");
                    }
                }

                this->StopCrackingClients();
                emit StopCracking();
                emit clientsStatusChanged();

                {
                    std::lock_guard<std::mutex> lock(clientsMutex);

                    // Reset all clients → Ready, do not log individually
                    for (auto& [id, state] : clientsReady) {
                        state.second = false;
                    }

                    // Clear current hash message after logging
                    currentHashMessage.clear();
                }
            }
        }
    } catch (...) {
        // Handle disconnect safely
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.erase(clientId);
        clientsReady.erase(clientId);
        emit logMessage("Cllient " + QString::fromStdString(clientId) + " has disconnected.");
        emit clientsStatusChanged();

        bool allIdle = std::all_of(clientsReady.begin(), clientsReady.end(),
                                   [](const auto& p) {
                                       return !p.second.second; // second = working flag
                                   });

        if (allIdle && !matchFound || clients.empty()) {
            emit StopCrackingNotStop();
            emit logMessage("No match was found.");
        } else if (allIdle){
            emit StopCrackingNotStop();
        }
    }
}

std::unordered_map<std::string, std::pair<std::string,bool>> ServerManager::getConnectedClientsStatus() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    return clientsReady;
}

void ServerManager::removeClientNickname(const std::string& clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clientsReady.find(clientId);
    if(it != clientsReady.end()) it->second.first = "";
}

// ------------------- Client Notifications ----------------------
void ServerManager::sendHashToClients(const QString& hashType, const QString& hash, const QString& salt) {
    start = std::chrono::high_resolution_clock::now();
    currentHashType = hashType;
    currentHash = hash;
    currentSalt = salt;
    matchFound = false;
    clientsResponded = 0;

    std::ostringstream oss;
    oss << currentHashType.toStdString() << ":" << currentHash.toStdString();
    if (!currentSalt.isEmpty()) oss << ":" << currentSalt.toStdString();
    oss << "\n";
    currentHashMessage = oss.str();

    bool found = false;
    QString decoded;
    for (auto& t : crackedHashes) {
        if (std::get<0>(t) == currentHash && std::get<1>(t) == currentSalt) {
            decoded = std::get<2>(t);
            found = true;
            break;
        }
    }

    if (found) {
        serverLogger.log("Found pre-cracked hash: " + currentHash.toStdString());
        emit logMessage("Found pre-cracked hash: " + currentHash + " Decoded: " + decoded);
        currentHashMessage.clear();
        emit StopCracking();
    } else {
        notifyClients();
        emit StartCracking();
        emit logMessage("Sent Hash to all connected clients.");
    }
}

void ServerManager::notifyClients() {
    std::vector<std::string> disconnectedClients;
    std::vector<std::pair<std::shared_ptr<boost::asio::ip::tcp::socket>, std::string>> socketsToNotify;

    {
        std::lock_guard<std::mutex> lock(clientsMutex);

        for (auto& [id, socket] : clients) {
            auto itReady = clientsReady.find(id);
            if (!socket || !socket->is_open() || itReady == clientsReady.end()) {
                disconnectedClients.push_back(id);
                continue;
            }

            // Only notify idle clients
            if (!itReady->second.second) {
                socketsToNotify.emplace_back(socket, id);
            }
        }

        // Remove disconnected clients safely
        for (const auto& id : disconnectedClients) {
            clients.erase(id);
            clientsReady.erase(id);
        }
    }

    if (!disconnectedClients.empty()) emit clientsStatusChanged();

    // Notify clients outside the lock to prevent blocking
    for (auto& [socket, id] : socketsToNotify) {
        std::thread([this, socket, id]() {
            try {
                boost::asio::write(*socket, boost::asio::buffer(currentHashMessage));

                // Mark client as working
                {
                    std::lock_guard<std::mutex> lock(clientsMutex);
                    auto it = clientsReady.find(id);
                    if (it != clientsReady.end()) {
                        it->second.second = true; // Working
                        emit clientReadyStateChanged(QString::fromStdString(id), false);
                    }
                }
            } catch (const boost::system::system_error& e) {
                emit logMessage("Failed to notify client: " + QString::fromStdString(id) +
                                " (" + QString::fromStdString(e.what()) + ")");
                // Remove disconnected client safely
                std::lock_guard<std::mutex> lock(clientsMutex);
                clients.erase(id);
                clientsReady.erase(id);
                emit clientsStatusChanged();
            }
        }).detach();
    }
}

void ServerManager::sendCatchup(std::shared_ptr<boost::asio::ip::tcp::socket> socket, const std::string& id) {
    std::string messageCopy;
    bool shouldSend = false;

    {
        std::lock_guard<std::mutex> lock(clientsMutex);

        // Only send catch-up if there is an active hash and at least one client is working
        bool anyWorking = std::any_of(clientsReady.begin(), clientsReady.end(),
                                      [](const auto& p){ return p.second.second; });

        if (!currentHashMessage.empty() && !matchFound && anyWorking) {
            messageCopy = currentHashMessage;
            shouldSend = true;
        }
    }

    if (!shouldSend) return;  // Nothing to send, exit early

    try {
        if (socket && socket->is_open()) {
            boost::asio::write(*socket, boost::asio::buffer(messageCopy));

            // Mark client as working
            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                auto it = clientsReady.find(id);
                if (it != clientsReady.end()) {
                    it->second.second = true; // Working
                    emit clientReadyStateChanged(QString::fromStdString(id), false);
                    emit logMessage("Sent catch-up command to client " + QString::fromStdString(id) + ".");
                }
            }
        }
    } catch (...) {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.erase(id);
        clientsReady.erase(id);
        emit clientsStatusChanged();
    }
}

void ServerManager::notifyStopAll() {
    std::vector<std::shared_ptr<boost::asio::ip::tcp::socket>> socketsToStop;

    // Collect alive sockets while holding the mutex
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        for (auto& [id, socket] : clients) {
            if (socket && socket->is_open()) {
                socketsToStop.push_back(socket);

                // Mark client idle immediately
                auto it = clientsReady.find(id);
                if (it != clientsReady.end()) it->second.second = false;
            }
        }
    }

    // Send STOP synchronously, outside the lock
    for (auto& socket : socketsToStop) {
        try {
            if (socket && socket->is_open())
                boost::asio::write(*socket, boost::asio::buffer("STOP\n"));
        } catch (const boost::system::system_error& e) {
            emit logMessage("Failed to send STOP: " + QString::fromStdString(e.what()));
        }
    }
}

// ------------------- Cracked Hashes ----------------------
void ServerManager::readCrackedHashes(const QString& file) {
    std::ifstream in(file.toStdString());
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string h, s, p;
        if (std::getline(iss, h, ':') && std::getline(iss, s, ':') && std::getline(iss, p))
            crackedHashes.emplace_back(QString::fromStdString(h), QString::fromStdString(s), QString::fromStdString(p));
    }
}

void ServerManager::reloadClients() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (auto& [id, socket] : clients) {
        if (socket && socket->is_open()) {
            try { boost::asio::write(*socket, boost::asio::buffer("reload\n")); }
            catch (...) {}
        }
    }
}
