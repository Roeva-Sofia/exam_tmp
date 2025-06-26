#include "mytcpserver.h"
#include "dbmanager.h"
#include <QDebug>
#include <QStringList>
#include <QSqlQuery>
#include <QSqlError>
#include <QRegularExpression>
#include <QString>
#include <cmath>

TcpServer::TcpServer(QObject* parent) : QObject(parent),
    m_server(new QTcpServer(this)),
    m_quizActive(false),
    m_currentQuestion(0)
{
    m_questions = {
        {"Столица Франции?", "Париж"},
        {"Сколько планет в Солнечной системе?", "8"},
        {"Автор романа 'Война и мир'?", "Толстой"}
    };

    if (!m_server->listen(QHostAddress::Any, 33333)) {
        qCritical() << "Failed to start server";
    } else {
        qInfo() << "Server started on port 33333";
        connect(m_server, &QTcpServer::newConnection,
                this, &TcpServer::handleNewConnection);
    }
}

TcpServer::~TcpServer()
{
    m_server->close();
    qDeleteAll(m_connectedClients);
}

bool TcpServer::allClientsAuthenticated() const
{
    for (auto socket : m_connectedClients) {
        if (!m_clientNames.contains(socket)) {
            return false;
        }
    }
    return true;
}

void TcpServer::handleNewConnection()
{
    QTcpSocket* clientSocket = m_server->nextPendingConnection();

    if (m_connectedClients.size() >= MAX_CLIENTS || m_quizActive) {
        sendResponse(clientSocket, "Server is busy. Please try again later.");
        clientSocket->disconnectFromHost();
        return;
    }

    m_connectedClients.append(clientSocket);
    m_scores[clientSocket] = 0;

    connect(clientSocket, &QTcpSocket::readyRead,
            this, [this, clientSocket]() {
                QString data = QString::fromUtf8(clientSocket->readAll());
                QStringList commands = data.split(QRegularExpression("[\r\n]+"), Qt::SkipEmptyParts);
                for (const QString& command : commands) {
                    processClientData(clientSocket, command);
                }
            });
    connect(clientSocket, &QTcpSocket::disconnected,
            this, [this, clientSocket]() { handleClientDisconnected(clientSocket); });

    sendResponse(clientSocket, "Welcome to Quiz Server! Please register or login.");
    broadcast(QString("New client connected. Total clients: %1").arg(m_connectedClients.size()));
}

void TcpServer::handleClientDisconnected(QTcpSocket* socket)
{
    m_connectedClients.removeAll(socket);
    m_clientNames.remove(socket);
    m_scores.remove(socket);
    socket->deleteLater();

    qInfo() << "Client disconnected";
    broadcast(QString("Client disconnected. Total clients: %1").arg(m_connectedClients.size()));

    if (m_quizActive) {
        endQuiz();
    }
}

void TcpServer::processClientData(QTcpSocket* socket, const QString& rawCommand)
{
    QString command = rawCommand.trimmed();
    if (command.isEmpty()) return;

    qDebug() << "Processing command:" << command;

    QStringList parts = command.split(" ", Qt::SkipEmptyParts);
    if (parts.isEmpty()) {
        sendResponse(socket, "Error: Empty command");
        return;
    }

    QString cmd = parts[0].toLower();
    QString args = parts.size() > 1 ? parts.mid(1).join(" ") : "";

    if (cmd == "reg") {
        processRegistration(socket, args);
    }
    else if (cmd == "auth") {
        processAuthentication(socket, args);
    }
    else if (cmd == "answer:" && m_quizActive) {
        processAnswer(socket, args);
    }
    else {
        sendResponse(socket, "Error: Unknown command or quiz not started");
    }
}

void TcpServer::processRegistration(QTcpSocket* socket, const QString& credentials)
{
    if (m_quizActive) {
        sendResponse(socket, "Quiz is active. Registration not allowed now.");
        return;
    }

    const QStringList parts = credentials.split(":");
    if (parts.size() != 2) {
        sendResponse(socket, "Error: Use format 'reg login:password'");
        return;
    }

    const QString login = parts[0].trimmed();
    const QString password = parts[1].trimmed();

    if (login.isEmpty() || password.isEmpty()) {
        sendResponse(socket, "Error: Login and password cannot be empty");
        return;
    }

    QString hashedPassword = DatabaseManager::hashPassword(password);

    QSqlQuery query(DatabaseManager::instance()->database());
    query.prepare("SELECT id FROM users WHERE login = :login");
    query.bindValue(":login", login);

    if (query.exec() && query.next()) {
        sendResponse(socket, "Error: User already exists");
        return;
    }

    query.prepare("INSERT INTO users (login, password) VALUES (:login, :password)");
    query.bindValue(":login", login);
    query.bindValue(":password", hashedPassword);

    if (query.exec()) {
        sendResponse(socket, "Registration successful. Please authenticate with: auth login:password");
    } else {
        sendResponse(socket, "Error: Registration failed");
        qWarning() << "Database error:" << query.lastError().text();
    }
}

void TcpServer::processAuthentication(QTcpSocket* socket, const QString& arguments)
{
    if (m_quizActive) {
        sendResponse(socket, "Quiz is active. Authentication not allowed now.");
        return;
    }

    QStringList creds = arguments.split(":", Qt::SkipEmptyParts);
    if (creds.size() != 2) {
        sendResponse(socket, "Error: Use format 'auth login:password'");
        return;
    }

    QString login = creds[0].trimmed();
    QString password = creds[1].trimmed();

    if (login.isEmpty() || password.isEmpty()) {
        sendResponse(socket, "Error: Login and password cannot be empty");
        return;
    }

    QString hashedPassword = DatabaseManager::hashPassword(password);

    QSqlQuery query(DatabaseManager::instance()->database());
    query.prepare("SELECT password FROM users WHERE login = :login");
    query.bindValue(":login", login);

    if (!query.exec()) {
        sendResponse(socket, "Error: Database error");
        return;
    }

    if (!query.next()) {
        sendResponse(socket, "Error: User not found. Register first with: reg login:password");
        return;
    }

    QString dbPassword = query.value(0).toString();
    if (dbPassword == hashedPassword) {
        m_clientNames[socket] = login;
        sendResponse(socket, "Authentication successful. Waiting for other players...");

        if (m_connectedClients.size() == MAX_CLIENTS && allClientsAuthenticated()) {
            startQuiz();
        }
    } else {
        sendResponse(socket, "Error: Invalid password");
    }
}

void TcpServer::startQuiz()
{
    m_quizActive = true;
    m_currentQuestion = 0;

    for (auto socket : m_connectedClients) {
        m_scores[socket] = 0;
    }

    broadcast("Quiz started! Get ready for the first question.");
    askQuestion();
}

void TcpServer::askQuestion()
{
    if (m_currentQuestion < m_questions.size()) {
        auto question = m_questions[m_currentQuestion].first;
        broadcast(QString("Question %1: %2").arg(m_currentQuestion + 1).arg(question));
    } else {
        endQuiz();
    }
}

void TcpServer::processAnswer(QTcpSocket* socket, const QString& answer)
{
    if (!m_quizActive || !m_clientNames.contains(socket)) {
        sendResponse(socket, "Error: You are not authenticated or quiz not active");
        return;
    }

    QString correctAnswer = m_questions[m_currentQuestion].second;
    QString userAnswer = answer.trimmed();

    if (QString::compare(userAnswer, correctAnswer, Qt::CaseInsensitive) == 0) {
        m_scores[socket]++;
        sendResponse(socket, "Correct answer!");
    } else {
        sendResponse(socket, QString("Wrong answer! Correct answer was: %1").arg(correctAnswer));
    }

    m_currentQuestion++;
    askQuestion();
}

void TcpServer::endQuiz()
{
    m_quizActive = false;

    int maxScore = 0;
    QList<QTcpSocket*> winners;

    for (auto socket : m_connectedClients) {
        if (m_scores[socket] > maxScore) {
            maxScore = m_scores[socket];
            winners.clear();
            winners.append(socket);
        } else if (m_scores[socket] == maxScore) {
            winners.append(socket);
        }
    }

    for (auto socket : m_connectedClients) {
        QString result;
        if (winners.contains(socket)) {
            result = QString("WIN! Your score: %1").arg(m_scores[socket]);
        } else {
            result = QString("Try again. Your score: %1").arg(m_scores[socket]);
        }
        sendResponse(socket, result);
    }

    for (auto socket : m_connectedClients) {
        socket->disconnectFromHost();
    }
}

void TcpServer::sendResponse(QTcpSocket* socket, const QString& message)
{
    if (socket && socket->state() == QTcpSocket::ConnectedState) {
        socket->write(message.toUtf8() + "\r\n");
    }
}

void TcpServer::broadcast(const QString& message)
{
    for (auto socket : m_connectedClients) {
        sendResponse(socket, message);
    }
}
