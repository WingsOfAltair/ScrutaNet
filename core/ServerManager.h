#pragma once

#include <QObject>
#include <QString>
#include <unordered_map>
#include <vector>
#include <tuple>
#include <string>
#include <thread>
#include <mutex>
#include <optional>
#include <memory>
#include <boost/asio.hpp>
#include "shared/AsyncLogger.h"
#include "shared/AsyncStorageLogger.h"

class ServerManager : public QObject {
    Q_OBJECT
public:
    explicit ServerManager(QObject* parent = nullptr);
    ~ServerManager();

    void StopCrackingClients();
    void setClientNickname(const std::string& clientId, const std::string& newNickname);
    void removeClientNickname(const std::string& clientId);
    void shutdownClient(const std::string& clientId);
    void restartClient(const std::string& clientId);
    std::unordered_map<std::string, std::pair<std::string,bool>> getConnectedClientsStatus();

    void sendHashToClients(const QString& hashType, const QString& hash, const QString& salt);
    void sendCatchup(std::shared_ptr<boost::asio::ip::tcp::socket> socket, const std::string& id);
    void reloadClients();

    void stopServer();

signals:
    void logMessage(const QString& message);
    void clientConnected(const QString& clientId);
    void clientReadyStateChanged(const QString& clientId, bool ready);
    void clientsStatusChanged();
    void StartCracking();
    void StopCracking();
    void StopCrackingNotStop();
    void StopCrackingZeroClients();

private:
    void startServer(int port);
    void handleClient(std::shared_ptr<boost::asio::ip::tcp::socket> socket);
    void notifyClients();
    void notifyStopAll();
    void udpEchoServer();
    void asyncAcceptClient();
    void readCrackedHashes(const QString& file);
    void logServer(const std::string& message);

private:
    std::unordered_map<std::string, std::shared_ptr<boost::asio::ip::tcp::socket>> clients;
    std::unordered_map<std::string, std::pair<std::string,bool>> clientsReady;
    std::vector<std::thread> serverThreads;
    std::unique_ptr<boost::asio::io_context> ioContext;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor;
    std::unique_ptr<boost::asio::ip::udp::socket> udpSocket;
    std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> workGuard;
    std::mutex clientsMutex;

    int totalClients = 0;
    int serverPort = 0;
    bool serverRunning = false;
    bool matchFound = false;
    int clientsResponded = 0;
    std::chrono::high_resolution_clock::time_point start;

    QString currentHashType;
    QString currentHash;
    QString currentSalt;
    QString currentPassword;

    std::string currentHashMessage; // store current task for new clients
    std::vector<std::tuple<QString, QString, QString>> crackedHashes;

    AsyncLogger serverLogger;
    AsyncStorageLogger crackedLogger;
};
